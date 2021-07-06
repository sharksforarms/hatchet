use hachet::datalink::{pcapfile::PcapFile, InterfaceReader};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let pcap_file = args.get(1).expect("expected a pcap_file as argument");

    // Read from interface
    let mut int = InterfaceReader::init::<PcapFile>(&pcap_file).unwrap();

    for (_i, pkt) in (&mut int).enumerate() {
        println!("Packet: {:?}", pkt);
    }
}
