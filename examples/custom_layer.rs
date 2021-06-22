use rust_packet::get_layer;
use rust_packet::layer::layers::Ipv4;
use rust_packet::layer::layers::Ipv4Builder;
use rust_packet::layer::layers::Tcp;
use rust_packet::layer::layers::TcpBuilder;
use rust_packet::layer::LayerError;
use rust_packet::layer::{layers::Ether, Layer, LayerBuilder, LayerExt, LayerOwned};
use rust_packet::packet::PacketBuilder;

#[derive(Debug, Default)]
struct Http {}

struct HttpBuilder {}

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

impl LayerBuilder for HttpBuilder {
    fn parse<'a>(&self, input: &'a [u8]) -> Result<(&'a [u8], Box<dyn LayerExt>), LayerError> {
        let (rest, http) = Http::parse(input)?;
        Ok((rest, Box::new(http)))
    }
}

fn main() {
    let mut pb = PacketBuilder::new();
    pb.bind_layer::<Ether, _>(|_from| Some(Box::new(Ipv4Builder {})));
    pb.bind_layer::<Ipv4, _>(|_from| Some(Box::new(TcpBuilder {})));

    pb.bind_layer::<Tcp, _>(|tcp: &Tcp| {
        if tcp.sport == 80 {
            Some(Box::new(HttpBuilder {}))
        } else {
            None
        }
    });

    let p = pb.parse_packet::<Ether>(b"asd").unwrap();
    dbg!(p);
}
