use crate::{
    layer::{
        ether::{Ether, EtherType},
        ip::{IpProtocol, Ipv4, Ipv6},
        raw::Raw,
        tcp::Tcp,
        LayerExt,
    },
    packet::PacketBuilder,
};

/// Create a [PacketBuilder](crate::packet::PacketBuilder) with a set of bindings using layers
/// defined in the crate
pub(crate) fn create_packetbuilder() -> PacketBuilder {
    let mut pb = PacketBuilder::without_bindings();

    pb.bind_layer(|ether: &Ether, _rest| match ether.ether_type {
        EtherType::IPv4 => Some(Ipv4::parse_layer),
        EtherType::IPv6 => Some(Ipv6::parse_layer),
        _ => Some(Raw::parse_layer),
    });

    pb.bind_layer(|ipv4: &Ipv4, _rest| match ipv4.protocol {
        IpProtocol::TCP => Some(Tcp::parse_layer),
        _ => Some(Raw::parse_layer),
    });

    pb.bind_layer(|ipv6: &Ipv6, _rest| match ipv6.next_header {
        IpProtocol::TCP => Some(Tcp::parse_layer),
        _ => Some(Raw::parse_layer),
    });

    pb.bind_layer(|_tcp: &Tcp, _rest| Some(Raw::parse_layer));

    pb
}
