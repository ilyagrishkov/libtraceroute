/*
   Copyright 2020 Ilya Grishkov

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

extern crate pnet;

pub(crate) mod packet_builder;

use pnet::datalink::{NetworkInterface, MacAddr, DataLinkSender, DataLinkReceiver};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::datalink::channel;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

pub enum Protocol {
    UDP,
    TCP,
    ICMP
}

pub(crate) struct Channel {
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
    packet_builder: packet_builder::PacketBuilder,
    payload_offset: usize,
    port: u16,
    ttl: u8,
    seq: u16,
}

impl Default for Channel {
    fn default() -> Self {
        let available_interfaces = get_available_interfaces();

        let default_interface = available_interfaces
            .iter()
            .next()
            .expect("no interfaces available")
            .clone();

        Channel::new(&default_interface, 33434, 1)
    }
}

impl Channel {
    pub fn new(network_interface: &NetworkInterface, port: u16, ttl: u8) -> Self {
        let source_ip = network_interface.ips
            .iter()
            .filter(|i| i.is_ipv4())
            .next()
            .expect("couldn't get interface IP")
            .ip()
            .to_string();

        let source_ip = Ipv4Addr::from_str(source_ip.as_str()).expect("malformed source ip");
        let payload_offset = if cfg!(any(target_os = "macos", target_os = "ios"))
            && network_interface.is_up() && !network_interface.is_broadcast()
            && ((!network_interface.is_loopback() && network_interface.is_point_to_point())
            || network_interface.is_loopback()) {
            if network_interface.is_loopback() { 14 } else { 0 }
        } else { 0 };

        let (tx, rx) = match channel(&network_interface, Default::default()) {
            Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("libtraceroute: unhandled util type"),
            Err(e) => panic!("libtraceroute: unable to create util: {}", e),
        };

        Channel {
            tx, rx,
            packet_builder: packet_builder::PacketBuilder::new(Protocol::UDP, network_interface.mac.unwrap(), source_ip),
            payload_offset,
            port, ttl,
            seq: 0
        }
    }

    /// Change protocol of packet_builder.
    pub(crate) fn change_protocol(&mut self, new_protocol: Protocol) {
        self.packet_builder.protocol = new_protocol;
    }

    pub(crate) fn increment_ttl(&mut self) -> u8 {
        self.ttl += 1;
        self.ttl - 1
    }

    /// Sends packet.
    pub(crate) fn send_to(&mut self, destination_ip: Ipv4Addr) {
        let buf = self.packet_builder.build_packet(destination_ip, self.ttl, self.port + self.seq);
        self.tx.send_to(&buf, None);
        self.seq += 1;
    }

    /// Waits for ICMP time-to-live-exceeded packet.
    pub(crate) fn recv(&mut self) -> String {
        let now = std::time::SystemTime::now();
        loop {
            match self.process_incoming_packet() {
                Ok(ip) => return ip,
                Err(_) => {
                    match now.elapsed() {
                        Ok(t) => {
                            if t.as_millis() > 500 {
                                return String::from("*");
                            }
                        }
                        Err(_) => return String::from("*")
                    }
                }
            }
        }
    }

    /// Start capturing packets until until expected ICMP packet was received.
    pub(crate) fn process_incoming_packet(&mut self) -> Result<String, &'static str> {
        match self.rx.next() {
            Ok(packet) => {
                if self.payload_offset > 0 && packet.len() > self.payload_offset {
                    return handle_ipv4_packet(&packet[self.payload_offset..]);
                }
                return handle_ethernet_frame(packet);
            }
            Err(e) => panic!("libtraceroute: unable to receive packet: {}", e),
        }
    }
}

/// Returns the list of interfaces that are up, not loopback and have an IPv4 address
/// and non-zero MAC address associated with them.
pub fn get_available_interfaces() -> Vec<NetworkInterface> {
    let all_interfaces = pnet::datalink::interfaces();

    let available_interfaces: Vec<NetworkInterface>;

    available_interfaces = if cfg!(target_family = "windows") {
        all_interfaces
            .into_iter()
            .filter(|e| e.mac.is_some()
                && e.mac.unwrap() != MacAddr::zero()
                && e.ips
                .iter()
                .filter(|ip| ip.ip().to_string() != "0.0.0.0")
                .next().is_some())
            .collect()
    } else {
        all_interfaces
            .into_iter()
            .filter(|e| e.is_up()
                && !e.is_loopback()
                && e.ips.iter().filter(|ip| ip.is_ipv4()).next().is_some()
                && e.mac.is_some()
                && e.mac.unwrap() != MacAddr::zero())
            .collect()
    };

    available_interfaces
}


// TODO: add checks for ICMP code icmp[1] = 0 and icmp[1] = 3
/// Processes ICMP packets. Returns addresses of packets that conform to the following
/// Berkeley Packet filter formula: `icmp and (icmp[0] = 11) or (icmp[0] = 3)`, thus
/// accepting all ICMP packets that have information about the status of UDP packets used for
/// traceroute.
fn handle_icmp_packet(source: IpAddr, packet: &[u8]) -> Result<String, &'static str> {
    let icmp_packet = IcmpPacket::new(packet).expect("malformed ICMP packet");

    match icmp_packet.get_icmp_type() {
        IcmpTypes::TimeExceeded => Ok(source.to_string()),
        IcmpTypes::DestinationUnreachable => Ok(source.to_string()),
        _ => Err("wrong packet")
    }
}

/// Processes IPv4 packet and passes it on to transport layer packet handler.
fn handle_ipv4_packet(packet: &[u8]) -> Result<String, &'static str> {
    let header = Ipv4Packet::new(packet).expect("malformed IPv4 packet");

    let source = IpAddr::V4(header.get_source());
    let payload = header.payload();

    match header.get_next_level_protocol() {
        IpNextHeaderProtocols::Icmp => handle_icmp_packet(source, payload),
        _ => Err("wrong packet")
    }
}

/// Processes ethernet frame and rejects all packets that are not IPv4.
fn handle_ethernet_frame(packet: &[u8]) -> Result<String, &'static str> {
    let ethernet = EthernetPacket::new(packet).expect("malformed Ethernet frame");
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => return handle_ipv4_packet(ethernet.payload()),
        _ => Err("wrong packet")
    }
}
