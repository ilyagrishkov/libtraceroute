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

use pnet::datalink::{NetworkInterface, MacAddr, DataLinkSender, DataLinkReceiver};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::{Packet, MutablePacket};
use pnet::datalink::channel;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use rand::Rng;

pub(crate) struct Channel {
    pub tx: Box<dyn DataLinkSender>,
    pub rx: Box<dyn DataLinkReceiver>,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
    payload_offset: usize,
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

        Channel::new(&default_interface)
    }
}

impl Channel {
    pub fn new(network_interface: &NetworkInterface) -> Self {
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

        Channel { source_ip, source_mac: network_interface.mac.unwrap(), tx, rx, payload_offset, seq: 0 }
    }

    /// Sends packet.
    pub(crate) fn send(&mut self, buf: &[u8]) {
        self.tx.send_to(buf, None);
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

    /// Create a new UDP packet with current TTL.
    pub(crate) fn build_udp_packet(&mut self, destination_ip: Ipv4Addr, ttl: u8, port: u16) -> Vec<u8> {
        let mut buf = [0u8; 66];
        let mut mut_ethernet_header = MutableEthernetPacket::new(&mut buf[..]).unwrap();

        mut_ethernet_header.set_destination(MacAddr::zero());
        mut_ethernet_header.set_source(self.source_mac);
        mut_ethernet_header.set_ethertype(EtherTypes::Ipv4);

        let mut ip_header = MutableIpv4Packet::new(mut_ethernet_header.payload_mut()).unwrap();

        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length(52);
        ip_header.set_ttl(ttl);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_header.set_source(self.source_ip);
        ip_header.set_destination(destination_ip);
        ip_header.set_checksum(pnet::packet::ipv4::checksum(&ip_header.to_immutable()));

        let mut udp_header = MutableUdpPacket::new(ip_header.payload_mut()).unwrap();

        udp_header.set_source(rand::thread_rng().gen_range(49152, 65535));
        udp_header.set_destination(port + self.seq);
        udp_header.set_length(32 as u16);
        udp_header.set_payload(&[0; 24]);
        udp_header.set_checksum(pnet::packet::udp::ipv4_checksum(&udp_header.to_immutable(),
                                                                 &self.source_ip, &destination_ip));

        self.seq += 1;
        buf.to_vec()
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
