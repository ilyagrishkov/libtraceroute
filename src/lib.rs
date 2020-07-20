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

//! # libtraceroute
//! `libtraceroute` provides a cross-platform API for traceroute using Rust.
//!
//! ## Features
//! `libtraceroute` sends and receives packets at a data link layer, which makes it
//! flexible and highly customisable. The library allows to configure the following parameters:
//! - Port
//! - Timeout per query (in _ms_)
//! - Maximum number of hops
//! - Number of queries per hop
//! - Network interface
//! - Protocol (UDP, TCP, ICMP)
//!
//! The library is based on [pnet](https://github.com/libpnet/libpnet) which allows
//! to work at Layer 2 (Data link) without root privileges on MacOS and Windows, but still requires
//! sudo on Linux.
//!
//! ## Example
//!
//! ### Traceroute with default configuration:
//!
//! ```rust,no-run,should_panic
//! extern crate libtraceroute;
//!
//! use libtraceroute::Traceroute;
//! use std::net::Ipv4Addr;
//!
//! fn main() {
//!     let destination_ip = Ipv4Addr::new(93, 184, 216, 34);  // example.com
//!
//!     let traceroute_query = Traceroute::new(destination_ip, Default::default());
//!
//!     for hop in traceroute_query {
//!         print!("{}", hop.ttl);
//!         for query_result in &hop.query_result {
//!             print!(" \t{}ms \t{}\n", query_result.rtt.as_millis(), query_result.addr);
//!         }
//!     }
//! }
//! ```
//!
//! ### Traceroute with custom configuration:
//!
//! ```rust,no-run,should_panic
//! extern crate libtraceroute;
//!
//! use libtraceroute::{Traceroute, Config};
//! use libtraceroute::util::{Protocol, get_available_interfaces};
//! use std::net::Ipv4Addr;
//!
//! fn main() {
//!     let destination_ip = Ipv4Addr::new(93, 184, 216, 34);  // example.com
//!
//!     let available_interfaces = get_available_interfaces();
//!
//!     let network_interface = match available_interfaces.iter().filter(|i| i.name == "en0").next() {
//!         Some(i) => i.clone(),
//!         None => panic!("no such interface available")
//!     };
//!
//!     let mut traceroute_query = Traceroute::new(destination_ip, Config::default()
//!         .with_port(33480)
//!         .with_max_hops(20)
//!         .with_first_ttl(2)
//!         .with_interface(network_interface)
//!         .with_number_of_queries(2)
//!         .with_protocol(Protocol::UDP)
//!         .with_timeout(1000));
//!
//!     // Calculate all hops upfront
//!     let traceroute_result = traceroute_query.perform_traceroute();
//!
//!     // Iterate over pre-calculated hops vector
//!     for hop in traceroute_result {
//!         print!("{}", hop.ttl);
//!         for query_result in &hop.query_result {
//!             print!(" \t{}ms \t{}\n", query_result.rtt.as_millis(), query_result.addr);
//!         }
//!     }
//! }
//! ```


extern crate pnet;

/// Miscellaneous utilities for for traceroute
pub mod util;

use pnet::datalink::NetworkInterface;
use std::net::Ipv4Addr;
use std::time::Duration;
use crate::util::Protocol;

/// Traceroute instance containing destination address and configurations
pub struct Traceroute {
    addr: Ipv4Addr,
    config: Config,
    done: bool,
}

/// Traceroute configurations
pub struct Config {
    port: u16,
    max_hops: u32,
    number_of_queries: u32,
    ttl: u8,
    timeout: Duration,
    channel: util::Channel,
}

/// Single traceroute hop containing TTL and a vector of traceroute query results
pub struct TracerouteHop {
    /// Current Time-To-Live
    pub ttl: u8,
    /// Traceroute query results
    pub query_result: Vec<TracerouteQueryResult>,
}

/// Result of a single query execution - IP and RTT
pub struct TracerouteQueryResult {
    /// Round-Trip Time
    pub rtt: Duration,
    /// IP address of a remote node
    pub addr: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {port: 33434, max_hops: 30, number_of_queries: 3, ttl: 1, timeout: Duration::from_secs(1), channel: Default::default()}
    }
}

impl Config {
    /// Builder: Port for traceroute. Will be incremented on every query (except for TCP-based traceroute)
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Builder: Maximum number of hops
    pub fn with_max_hops(mut self, max_hops: u32) -> Self {
        self.max_hops = max_hops;
        self
    }

    /// Builder: Number of queries to run per hop
    pub fn with_number_of_queries(mut self, number_of_queries: u32) -> Self {
        self.number_of_queries = number_of_queries;
        self
    }

    /// Builder: Protocol. Supported: UDP, TCP, ICMP
    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.channel.change_protocol(protocol);
        self
    }

    /// Builder: Interface that will be used for sending and receiving packets
    pub fn with_interface(mut self, network_interface: NetworkInterface) -> Self {
        self.channel = util::Channel::new(network_interface, self.port, self.ttl);
        self
    }

    /// Builder: First TTL to record
    pub fn with_first_ttl(mut self, first_ttl: u8) -> Self {
        self.ttl = first_ttl;
        self
    }

    /// Builder: Timeout per query
    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = Duration::from_millis(timeout);
        self
    }
}

impl Iterator for Traceroute {
    type Item = TracerouteHop;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.config.channel.max_hops_reached(self.config.max_hops as u8) {
            return None;
        }

        let hop = self.calculate_next_hop();
        self.done = hop.query_result.iter()
            .filter(|ip| ip.addr == self.addr.to_string())
            .next().is_some();
        Some(hop)
    }
}

impl Traceroute {
    /// Creates new instance of Traceroute
    pub fn new(addr: Ipv4Addr, config: Config) -> Self {
        Traceroute {
            addr,
            config,
            done: false,
        }
    }

    /// Returns a vector of traceroute hops
    pub fn perform_traceroute(&mut self) -> Vec<TracerouteHop> {
        let mut hops = Vec::<TracerouteHop>::new();
        for _ in 1..self.config.max_hops {
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

    /// Get next hop on the route. Increases TTL
    fn calculate_next_hop(&mut self) -> TracerouteHop {
        let mut query_results = Vec::<TracerouteQueryResult>::new();
        for _ in 0..self.config.number_of_queries {
            let result = self.get_next_query_result();
            if result.addr == "*" || query_results.iter()
                .filter(|query_result| query_result.addr == result.addr)
                .next().is_none() {
                query_results.push(result)
            }
        }
        TracerouteHop { ttl: self.config.channel.increment_ttl(), query_result: query_results }
    }

    /// Runs a query to the destination and returns RTT and IP of the router where
    /// time-to-live-exceeded. Doesn't increase TTL
    fn get_next_query_result(&mut self) -> TracerouteQueryResult {
        let now = std::time::SystemTime::now();

        self.config.channel.send_to(self.addr);
        let hop_ip = self.config.channel.recv_timeout(Duration::from_secs(1));
        TracerouteQueryResult {
            rtt: now.elapsed().unwrap_or(Duration::from_millis(0)),
            addr: hop_ip,
        }
    }
}
