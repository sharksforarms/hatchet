use deku::DekuContainerRead;
use hachet::{
    datalink::{pcap::Pcap, Interface, PacketInterfaceSplit, PacketWrite},
    layer::{ether::Ether, ip::Ipv4, raw::Raw, tcp::Tcp, LayerOwned},
    packet::Packet,
};

fn main() {
    // Read from interface
    let int = Interface::init::<Pcap>("lo").unwrap();

    let (mut rx, mut tx) = int.into_split();
    //let (mut rx, mut tx) = int.split();

    for (_i, pkt) in (&mut rx).enumerate() {
        println!("Packet: {:?}", pkt);

        // send a hello world for every packet
        let layers: Vec<LayerOwned> = vec![
            Box::new(Ether::default()),
            Box::new(Ipv4::default()),
            Box::new(Tcp::default()),
            Box::new(Raw::from_bytes((b"hello world", 0)).unwrap().1),
        ];
        let mut p = Packet::from_layers(layers);
        p.finalize().unwrap();
        tx.write(p).unwrap();
    }
}
