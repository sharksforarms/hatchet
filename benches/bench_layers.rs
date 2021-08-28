#[macro_use]
extern crate criterion;

use criterion::black_box;
use criterion::Criterion;

use hatchet::layer::ether::Ether;
use hatchet::layer::ip::{Ipv4, Ipv6};
use hatchet::layer::raw::Raw;
use hatchet::layer::tcp::Tcp;
use hatchet::layer::udp::Udp;
use hatchet::layer::LayerExt;

macro_rules! gen_header_bench {
    ($crit:ident, $name:ident, $data:expr, $layer:ident) => {
        $crit.bench_function(concat!(stringify!($name), "_from_bytes"), |b| {
            let data = $data.clone();
            b.iter(|| $layer::parse(black_box(&data)).expect("expected Ok"))
        });

        $crit.bench_function(concat!(stringify!($name), "_to_bytes"), |b| {
            let (_rest, layer) = $layer::parse(&$data.clone()).unwrap();
            b.iter(|| layer.to_bytes().expect("expected Ok"))
        });
    };
}

pub fn criterion_benchmark(c: &mut Criterion) {
    gen_header_bench!(c, bench_raw, Raw::default().to_bytes().unwrap(), Raw);
    gen_header_bench!(c, bench_ether, Ether::default().to_bytes().unwrap(), Ether);
    gen_header_bench!(c, bench_ipv4, Ipv4::default().to_bytes().unwrap(), Ipv4);
    gen_header_bench!(c, bench_ipv6, Ipv6::default().to_bytes().unwrap(), Ipv6);
    gen_header_bench!(c, bench_tcp, Tcp::default().to_bytes().unwrap(), Tcp);
    gen_header_bench!(c, bench_udp, Udp::default().to_bytes().unwrap(), Udp);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
