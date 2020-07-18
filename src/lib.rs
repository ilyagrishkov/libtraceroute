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

use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::{Packet, MutablePacket};
use pnet::datalink::{channel, NetworkInterface, DataLinkReceiver, DataLinkSender};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use pnet::util::MacAddr;
use std::str::FromStr;
use rand::Rng;

pub struct Traceroute {
    addr: String,
    port: u16,
    max_hops: u32,
    number_of_queries: u32,
    interface: NetworkInterface,
    ttl: u8,
    datalink_receiver: Box<dyn DataLinkReceiver>,
    datalink_sender: Box<dyn DataLinkSender>,
    done: bool,
    seq: u16,
}

pub struct TracerouteHop {
    pub ttl: u8,
    pub query_result: Vec<TracerouteQueryResult>,
}

pub struct TracerouteQueryResult {
    pub rtt: Duration,
    pub addr: String,
}

impl Iterator for Traceroute {
    type Item = TracerouteHop;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let hop = self.calculate_next_hop();
        match hop {
            Ok(h) => {
                self.done = h.query_result.iter()
                    .filter(|ip| ip.addr == self.addr)
                    .next().is_some()
                    || self.ttl > self.max_hops as u8;
                Some(h)
            }
            Err(_) => None
        }
    }
}

impl Traceroute {
    /// Creates new instance of TracerouteQuery.
    pub fn new(addr: String, port: u16, max_hops: u32, number_of_queries: u32) -> Self {
        let available_interfaces = get_available_interfaces()
            .expect("couldn't get available interfaces");

        let default_interface = available_interfaces.get(0)
            .expect("couldn't get default interface").clone();

        let (tx, rx) = match channel(&default_interface, Default::default()) {
            Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("libtraceroute: unhandled channel type"),
            Err(e) => panic!("libtraceroute: unable to create channel: {}", e),
        };

        Traceroute {
            addr,
            port,
            max_hops,
            number_of_queries,
            interface: default_interface,
            ttl: 1,
            datalink_receiver: rx,
            datalink_sender: tx,
            done: false,
            seq: 0,
        }
    }

    /// Returns a vector of traceroute hops.
    pub fn perform_traceroute(&mut self) -> Vec<TracerouteHop> {
        let mut hops = Vec::<TracerouteHop>::new();
        for _ in 1..self.max_hops {
            if self.done {
                return hops;
            }
            match self.next() {
                Some(hop) => hops.push(hop),
                None => {}
            }
        }
        return hops;
    }

    /// Get next hop on the route. Increases TTL.
    fn calculate_next_hop(&mut self) -> Result<TracerouteHop, &'static str> {
        let mut query_results = Vec::<TracerouteQueryResult>::new();
        for _ in 0..self.number_of_queries {
            match self.get_next_query_result() {
                Ok(v) => {
                    if query_results.iter()
                        .filter(|query_result| query_result.addr == v.addr)
                        .next().is_none() {
                        query_results.push(v)
                    }
                }
                Err(_) => query_results.push(TracerouteQueryResult { rtt: Duration::from_millis(0), addr: String::from("*") })
            }
        }
        self.ttl += 1;
        Ok(TracerouteHop { ttl: self.ttl - 1, query_result: query_results })
    }

    // TODO: find a cleaner and more reliable way of timeout.
    /// Runs a query to the destination and returns RTT and IP of the router where
    /// time-to-live-exceeded. Doesn't increase TTL.
    fn get_next_query_result(&mut self) -> Result<TracerouteQueryResult, &'static str> {
        let now = std::time::SystemTime::now();

        let mut buf = [0u8; 66];
        self.build_udp_packet(&mut buf);
        self.seq += 1;

        self.datalink_sender.send_to(&buf, None);

        let hop_ip: String = loop {
            match process_incoming_packet(&mut self.datalink_receiver, &self.interface) {
                Ok(ip) => break ip,
                Err(_) => {
                    match now.elapsed() {
                        Ok(t) => {
                            if t.as_millis() > 500 {
                                break String::from("*");
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
        };
        Ok(TracerouteQueryResult {
            rtt: now.elapsed().unwrap_or(Duration::from_millis(0)),
            addr: hop_ip,
        })
    }

    /// Create a new UDP packet with current TTL.
    fn build_udp_packet(&self, buf: &mut [u8]) {
        let source_ip = self.interface.ips
            .iter()
            .filter(|i| i.is_ipv4())
            .next()
            .expect("couldn't get interface IP")
            .ip()
            .to_string();

        let source_ip = Ipv4Addr::from_str(source_ip.as_str()).expect("malformed source ip");
        let destination_ip = Ipv4Addr::from_str(self.addr.as_str()).expect("malformed destination ip");

        let mut mut_ethernet_header = MutableEthernetPacket::new(&mut buf[..]).unwrap();

        mut_ethernet_header.set_destination(MacAddr::zero());
        mut_ethernet_header.set_source(self.interface.mac.expect("couldn't get source MAC"));
        mut_ethernet_header.set_ethertype(EtherTypes::Ipv4);

        let mut ip_header = MutableIpv4Packet::new(mut_ethernet_header.payload_mut()).unwrap();

        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length(52);
        ip_header.set_ttl(self.ttl);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_header.set_source(source_ip);
        ip_header.set_destination(destination_ip);
        ip_header.set_checksum(pnet::packet::ipv4::checksum(&ip_header.to_immutable()));

        let mut udp_header = MutableUdpPacket::new(ip_header.payload_mut()).unwrap();

        udp_header.set_source(rand::thread_rng().gen_range(49152, 65535));
        udp_header.set_destination(self.port + self.seq);
        udp_header.set_length(32 as u16);
        udp_header.set_payload(&[0; 24]);
        udp_header.set_checksum(pnet::packet::udp::ipv4_checksum(&udp_header.to_immutable(),
                                                                 &source_ip, &destination_ip));
    }
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

/// Start capturing packets until until expected ICMP packet was received.
fn process_incoming_packet(rx: &mut Box<dyn DataLinkReceiver>,
                           interface: &NetworkInterface) -> Result<String, &'static str> {
    match rx.next() {
        Ok(packet) => {
            if cfg!(any(target_os = "macos", target_os = "ios"))
                && interface.is_up() && !interface.is_broadcast()
                && ((!interface.is_loopback() && interface.is_point_to_point())
                || interface.is_loopback()) {
                let payload_offset = if interface.is_loopback() { 14 } else { 0 };
                if packet.len() > payload_offset {
                    return handle_ipv4_packet(&packet[payload_offset..]);
                }
            }
            return handle_ethernet_frame(packet);
        }
        Err(e) => panic!("libtraceroute: unable to receive packet: {}", e),
    }
}

/// Returns the list of interfaces that are up, not loopback and have an IPv4 address
/// and non-zero MAC address associated with them.
fn get_available_interfaces() -> Result<Vec<NetworkInterface>, &'static str> {
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
    Ok(available_interfaces)
}
