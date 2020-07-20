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

use libtraceroute::{Traceroute, Config};
use libtraceroute::util::Protocol::UDP;
use std::net::Ipv4Addr;

fn main() {
    let destination_ip = Ipv4Addr::new(93, 184, 216, 34);  // example.com

    let mut traceroute_query = Traceroute::new(destination_ip, Config::default()
        .with_port(33480)
        .with_max_hops(20)
        .with_first_ttl(2)
        .with_interface("en0")
        .with_number_of_queries(2)
        .with_protocol(UDP)
        .with_timeout(1000));

    // Calculate all hops upfront
    let traceroute_result = traceroute_query.perform_traceroute();

    // Iterate over pre-calculated hops vector
    for hop in traceroute_result {
        print!("{}", hop.ttl);
        for query_result in &hop.query_result {
            print!(" \t{}ms \t{}\n", query_result.rtt.as_millis(), query_result.addr);
        }
    }
}