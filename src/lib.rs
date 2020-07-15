/*
Copyright (c) 2020 Ilya Grishkov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
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

pub struct TracerouteQuery {
    addr: String,
    port: u16,
    max_hops: u32,
    interface: NetworkInterface,
    ttl: u8,
    datalink_receiver: Box<dyn DataLinkReceiver>,
    datalink_sender: Box<dyn DataLinkSender>,
    done: bool,
}

pub struct TracerouteHop {
    pub ttl: u8,
    pub rtt: Duration,
    pub addr: String,
}

impl Iterator for TracerouteQuery {
    type Item = TracerouteHop;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let hop = self.get_next_hop();
        match hop {
            Ok(h) => {
                self.done = h.addr == self.addr;
                Some(h)
            }
            Err(_) => None
        }
    }
}

impl TracerouteQuery {
    /// Creates new instance of TracerouteQuery.
    pub fn new(addr: String, port: u16, max_hops: u32) -> Self {
        let default_interface = get_default_interface()
            .expect("couldn't find default interface");

        let (tx, rx) = match channel(&default_interface, Default::default()) {
            Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("libtraceroute: unhandled channel type"),
            Err(e) => panic!("libtraceroute: unable to create channel: {}", e),
        };

        TracerouteQuery {
            addr,
            port,
            max_hops,
            interface: default_interface,
            ttl: 1,
            datalink_receiver: rx,
            datalink_sender: tx,
            done: false,
        }
    }

    // TODO: find a cleaner and more reliable way of timeout.
    /// Get next hop on the route. Increases TTL.
    pub fn get_next_hop(&mut self) -> Result<TracerouteHop, &'static str> {
        let now = std::time::SystemTime::now();

        let mut buf = [0u8; 42];
        self.build_udp_packet(&mut buf);

        self.datalink_sender.send_to(&buf, None);

        let hop_ip: String = loop {
            match process_incoming_packet(&mut self.datalink_receiver, &self.interface) {
                Ok(ip) => break ip,
                Err(_) => {
                    match now.elapsed() {
                        Ok(t) => {
                            if t.as_secs() > 2 {
                                break String::from("*");
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
        };
        self.ttl += 1;
        Ok(TracerouteHop { ttl: self.ttl - 1, rtt: Duration::from_millis(10), addr: hop_ip })
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
        ip_header.set_total_length(28);
        ip_header.set_ttl(self.ttl);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_header.set_source(source_ip);
        ip_header.set_destination(destination_ip);
        ip_header.set_checksum(pnet::packet::ipv4::checksum(&ip_header.to_immutable()));

        let mut udp_header = MutableUdpPacket::new(ip_header.payload_mut()).unwrap();

        udp_header.set_source(self.port);
        udp_header.set_destination(self.port);
        udp_header.set_length(8 as u16);
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

// TODO: find a more reliable way of detecting the default interface
// TODO: accept users specified interface
// NOTE: current implementation doesn't work on Windows
/// Returns the first interface that is up, loopback and has an IP address associated with it.
fn get_default_interface() -> Result<NetworkInterface, &'static str> {
    let interfaces = pnet::datalink::interfaces();

    let interface;

    interface = if cfg!(target_family = "windows") {
        interfaces
            .iter()
            .filter(|e| e.mac.is_some() && e.ips.iter().filter(|ip| ip.ip().to_string() != "0.0.0.0").next().is_some())
            .next()
    } else {
        interfaces
            .iter()
            .filter(|e| e.is_up() && !e.is_loopback() && e.ips.len() > 0 && e.mac.is_some())
            .next()
    };

    match interface {
        Some(i) => Ok(i.clone()),
        None => Err("libtraceroute: couldn't find default interface")
    }
}
