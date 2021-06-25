use hexlit::hex;
use rust_packet::get_layer;
use rust_packet::layer::ether::Ether;
use rust_packet::layer::ip::Ipv4;
use rust_packet::layer::tcp::Tcp;
use rust_packet::layer::LayerError;
use rust_packet::layer::{Layer, LayerExt, LayerOwned};
use rust_packet::packet::PacketBuilder;

#[derive(Debug, Default)]
struct Http {
    data: String,
}

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
        let http = Http {
            data: String::from_utf8_lossy(input).to_string(),
        };
        Ok(([].as_ref(), http))
    }
}

fn main() {
    let mut pb = PacketBuilder::new();
    pb.bind_layer::<Ether, _>(|_from| Some(Ipv4::parse_layer));
    pb.bind_layer::<Ipv4, _>(|_from| Some(Tcp::parse_layer));

    pb.bind_layer::<Tcp, _>(|tcp: &Tcp| {
        if tcp.dport == 80 {
            Some(Http::parse_layer)
        } else {
            None
        }
    });

    // Ether / IP / TCP / "hello world"
    let test_data = hex!("ffffffffffff0000000000000800450000330001000040067cc27f0000017f00000100140050000000000000000050022000ffa2000068656c6c6f20776f726c64");
    let (_rest, p) = pb.parse_packet::<Ether>(&test_data).unwrap();
    dbg!(p);
}
