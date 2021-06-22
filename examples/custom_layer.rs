use rust_packet::get_layer;
use rust_packet::layer::layers::Ipv4;
use rust_packet::layer::layers::Tcp;
use rust_packet::layer::LayerError;
use rust_packet::layer::{layers::Ether, Layer, LayerExt, LayerOwned};
use rust_packet::packet::PacketBuilder;

#[derive(Debug, Default)]
struct Http {}

impl Layer for Http {}
impl LayerExt for Http {
    fn finalize(&mut self, prev: &[LayerOwned], _next: &[LayerOwned]) -> Result<(), LayerError> {
        if let Some(prev_layer) = prev.last() {
            if let Some(tcp) = get_layer!(prev_layer, Tcp) {
                dbg!(tcp);
            }
        }

        Ok(())
    }

    fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    where
        Self: Sized,
    {
        Ok((input, Http {}))
    }
}

fn main() {
    let mut pb = PacketBuilder::new();
    pb.bind_layer::<Ether, _>(|_from| Some(Ipv4::parse_layer));
    pb.bind_layer::<Ipv4, _>(|_from| Some(Tcp::parse_layer));

    pb.bind_layer::<Tcp, _>(|tcp: &Tcp| {
        if tcp.sport == 80 {
            Some(Http::parse_layer)
        } else {
            None
        }
    });

    let p = pb.parse_packet::<Ether>(b"asd").unwrap();
    dbg!(p);
}
