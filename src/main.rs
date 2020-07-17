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

use libtraceroute::TracerouteQuery;

// NOTE: this crate is supposed to be a library. Main exists temporarily for testing purposes only
fn main() {
    let addr = "93.184.216.34";
    let port = 33434;
    let max_hops = 30;

    let query = TracerouteQuery::new(String::from(addr), port, max_hops);

    for hop in query {
        println!("{} \t {}ms \t {}", hop.ttl, hop.rtt.as_millis(), hop.addr);
    }
}
