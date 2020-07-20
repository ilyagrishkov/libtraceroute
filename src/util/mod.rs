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

use pnet::datalink::{NetworkInterface, MacAddr};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::datalink::channel;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;
use async_std::task::block_on;

#[derive(PartialEq)]
/// Protocol to be used for traceroute
pub enum Protocol {
    /// UDP-based traceroute
    UDP,
    /// TCP-based traceroute
    TCP,
    /// ICMP-based traceroute
    ICMP
}

pub(crate) struct Channel {
    interface: NetworkInterface,
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

        Channel::new(default_interface, 33434, 1)
    }
}

impl Channel {
    pub fn new(network_interface: NetworkInterface, port: u16, ttl: u8) -> Self {
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

        Channel {
            interface: network_interface.clone(),
            packet_builder: packet_builder::PacketBuilder::new(Protocol::UDP, network_interface.mac.unwrap(), source_ip),
            payload_offset,
            port, ttl,
            seq: 0
        }
    }

    /// Change protocol of packet_builder
    pub(crate) fn change_protocol(&mut self, new_protocol: Protocol) {
        self.packet_builder.protocol = new_protocol;
    }

    /// Increments current TTL
    pub(crate) fn increment_ttl(&mut self) -> u8 {
        self.ttl += 1;
        self.ttl - 1
    }

    /// Checks whether the current TTL exceeds maximum number of hops
    pub(crate) fn max_hops_reached(&self, max_hops: u8) -> bool {
        self.ttl > max_hops
    }

    /// Sends a packet
    pub(crate) fn send_to(&mut self, destination_ip: Ipv4Addr) {
        let (mut tx, _) = match channel(&self.interface, Default::default()) {
            Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("libtraceroute: unhandled util type"),
            Err(e) => panic!("libtraceroute: unable to create util: {}", e),
        };
        let buf = self.packet_builder.build_packet(destination_ip, self.ttl, self.port + self.seq);
        tx.send_to(&buf, None);
        if self.packet_builder.protocol != Protocol::TCP {
            self.seq += 1;
        }
    }

    /// Waits for the expected ICMP packet for specified amount of time
    pub(crate) fn recv_timeout(&mut self, timeout: Duration) -> String {
        let processor = async_std::task::spawn(Self::recv(self.interface.clone(), self.payload_offset));
        let ip = block_on(async {
            match async_std::future::timeout(timeout, processor).await {
                Ok(ip) => ip,
                Err(_) => String::from("*")
            }
        });
        ip
    }

    /// Waits for the expected ICMP packet to arrive until interrupted.
    async fn recv(interface: NetworkInterface, payload_offset: usize) -> String {
        loop {
            match process_incoming_packet(interface.clone(), payload_offset) {
                Ok(ip) => return ip,
                Err(_) => {}
            }
        }
    }
}

/// Returns the list of interfaces that are up, not loopback, not point-to-point,
/// and have an IPv4 address associated with them.
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
        IcmpTypes::EchoReply => Ok(source.to_string()),
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

/// Start capturing packets until until expected ICMP packet was received.
fn process_incoming_packet(interface: NetworkInterface, payload_offset: usize) -> Result<String, &'static str> {
    let (_, mut rx) = match channel(&interface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("libtraceroute: unhandled util type"),
        Err(e) => panic!("libtraceroute: unable to create util: {}", e),
    };
    match rx.next() {
        Ok(packet) => {
            if payload_offset > 0 && packet.len() > payload_offset {
                return handle_ipv4_packet(&packet[payload_offset..]);
            }
            return handle_ethernet_frame(packet);
        }
        Err(e) => panic!("libtraceroute: unable to receive packet: {}", e),
    }
}
