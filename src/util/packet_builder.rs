use crate::util::Protocol;
use rand::Rng;
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::icmp::{IcmpTypes, IcmpCode, MutableIcmpPacket};
use pnet::packet::MutablePacket;
use std::net::Ipv4Addr;

pub struct PacketBuilder {
    pub(crate) protocol: Protocol,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
}

impl PacketBuilder {
    pub fn new(protocol: Protocol, source_mac: MacAddr, source_ip: Ipv4Addr) -> Self {
        PacketBuilder { source_mac, source_ip, protocol }
    }

    pub fn build_packet(&self, destination_ip: Ipv4Addr, ttl: u8, port: u16) -> Vec<u8> {
        match self.protocol {
            Protocol::UDP => Self::build_udp_packet(self.source_mac, self.source_ip, destination_ip, ttl, port),
            Protocol::TCP => Self::build_tcp_packet(self.source_mac, self.source_ip, destination_ip, ttl, port),
            Protocol::ICMP => Self::build_icmp_packet(self.source_mac, self.source_ip, destination_ip, ttl)
        }
    }

    /// Create a new UDP packet.
    fn build_udp_packet(source_mac: MacAddr, source_ip: Ipv4Addr, destination_ip: Ipv4Addr, ttl: u8, port: u16) -> Vec<u8> {
        let mut buf = [0u8; 66];
        let mut mut_ethernet_header = MutableEthernetPacket::new(&mut buf[..]).unwrap();

        mut_ethernet_header.set_destination(MacAddr::zero());
        mut_ethernet_header.set_source(source_mac);
        mut_ethernet_header.set_ethertype(EtherTypes::Ipv4);

        let mut ip_header = MutableIpv4Packet::new(mut_ethernet_header.payload_mut()).unwrap();

        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length(52);
        ip_header.set_ttl(ttl);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_header.set_source(source_ip);
        ip_header.set_destination(destination_ip);
        ip_header.set_checksum(pnet::packet::ipv4::checksum(&ip_header.to_immutable()));

        let mut udp_header = MutableUdpPacket::new(ip_header.payload_mut()).unwrap();

        udp_header.set_source(rand::thread_rng().gen_range(49152, 65535));
        udp_header.set_destination(port);
        udp_header.set_length(32 as u16);
        udp_header.set_payload(&[0; 24]);
        udp_header.set_checksum(pnet::packet::udp::ipv4_checksum(&udp_header.to_immutable(),
                                                                 &source_ip, &destination_ip));

        buf.to_vec()
    }

    /// Create a new ICMP packet.
    fn build_icmp_packet(source_mac: MacAddr, source_ip: Ipv4Addr, destination_ip: Ipv4Addr, ttl: u8) -> Vec<u8> {
        let mut buf = [0u8; 86];
        let mut mut_ethernet_header = MutableEthernetPacket::new(&mut buf[..]).unwrap();

        mut_ethernet_header.set_destination(MacAddr::zero());
        mut_ethernet_header.set_source(source_mac);
        mut_ethernet_header.set_ethertype(EtherTypes::Ipv4);

        let mut ip_header = MutableIpv4Packet::new(mut_ethernet_header.payload_mut()).unwrap();

        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length(72);
        ip_header.set_ttl(ttl);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ip_header.set_source(source_ip);
        ip_header.set_destination(destination_ip);
        ip_header.set_checksum(pnet::packet::ipv4::checksum(&ip_header.to_immutable()));

        let mut icmp_header = MutableIcmpPacket::new(ip_header.payload_mut()).unwrap();

        icmp_header.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_header.set_icmp_code(IcmpCode::new(0));
        icmp_header.set_payload(&[0; 44]);
        icmp_header.set_checksum(pnet::packet::icmp::checksum(&icmp_header.to_immutable()));

        buf.to_vec()
    }

    /// Create a new TCP packet.
    fn build_tcp_packet(source_mac: MacAddr, source_ip: Ipv4Addr, destination_ip: Ipv4Addr, ttl: u8, port: u16) -> Vec<u8> {
        let mut buf = [0u8; 78];
        let mut mut_ethernet_header = MutableEthernetPacket::new(&mut buf[..]).unwrap();

        mut_ethernet_header.set_destination(MacAddr::zero());
        mut_ethernet_header.set_source(source_mac);
        mut_ethernet_header.set_ethertype(EtherTypes::Ipv4);

        let mut ip_header = MutableIpv4Packet::new(mut_ethernet_header.payload_mut()).unwrap();

        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length(64);
        ip_header.set_ttl(ttl);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(source_ip);
        ip_header.set_destination(destination_ip);
        ip_header.set_checksum(pnet::packet::ipv4::checksum(&ip_header.to_immutable()));

        let mut tcp_header = MutableTcpPacket::new(ip_header.payload_mut()).unwrap();

        tcp_header.set_source(rand::thread_rng().gen_range(49152, 65535));
        tcp_header.set_destination(port);
        tcp_header.set_sequence(0);
        tcp_header.set_acknowledgement(0);
        tcp_header.set_data_offset(5);
        tcp_header.set_reserved(0);
        tcp_header.set_flags(0x002);
        tcp_header.set_window(0);
        tcp_header.set_payload(&[0; 24]);
        tcp_header.set_checksum(pnet::packet::tcp::ipv4_checksum(&tcp_header.to_immutable(),
                                                                 &source_ip, &destination_ip));

        buf.to_vec()
    }
}
