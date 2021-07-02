use hachet::datalink::{pnet::Pnet, Interface, PacketInterface};

fn main() {
    // Read from interface
    let mut int = Interface::<Pnet>::init("lo").unwrap();

    for (_i, pkt) in (&mut int).enumerate() {
        println!("Packet: {:?}", pkt);
    }
}
