use hatchet::layer::ether::Ether;
use hatchet::layer::ip::Ipv4;
use hatchet::layer::tcp::Tcp;
use hatchet::layer::LayerError;
use hatchet::layer::{Layer, LayerExt, LayerOwned};
use hatchet::packet::PacketParser;
use hexlit::hex;

#[derive(Debug, Default, Clone)]
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

    fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
        todo!()
    }
}

fn main() {
    let mut pb = PacketParser::new();
    pb.bind_layer(|_from: &Ether, _rest| Some(Ipv4::parse_layer));
    pb.bind_layer(|_from: &Ipv4, _rest| Some(Tcp::parse_layer));

    pb.bind_layer(|tcp: &Tcp, _rest| {
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
