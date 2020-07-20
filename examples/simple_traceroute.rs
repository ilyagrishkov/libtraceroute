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

extern crate libtraceroute;

use libtraceroute::Traceroute;
use std::net::Ipv4Addr;

fn main() {
    let destination_ip = Ipv4Addr::new(93, 184, 216, 34);  // example.com

    let traceroute_query = Traceroute::new(destination_ip, Default::default());

    // Traceroute implements Iterator
    for hop in traceroute_query {
        print!("{}", hop.ttl);
        for query_result in &hop.query_result {
            print!(" \t{}ms \t{}\n", query_result.rtt.as_millis(), query_result.addr);
        }
    }
}