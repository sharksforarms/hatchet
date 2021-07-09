/*!
TCP layer
*/
use crate::get_layer;
use crate::layer::ip::{IpProtocol, Ipv4, Ipv6};
use crate::layer::{Layer, LayerError, LayerExt, LayerOwned};
use alloc::{format, string::ToString, vec::Vec};
use core::convert::TryFrom;
use deku::bitvec::{BitSlice, Msb0};
use deku::prelude::*;

mod options;
pub use options::{SAckData, TcpOption, TimestampData};

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(
    endian = "endian",
    ctx = "endian: deku::ctx::Endian",
    ctx_default = "deku::ctx::Endian::Big"
)]
#[allow(missing_docs)]
pub struct TcpFlags {
    #[deku(bits = "3")]
    pub reserved: u8,
    #[deku(bits = "1")]
    pub nonce: u8,
    /// Congestion Window Reduced (CWR)
    #[deku(bits = "1")]
    pub crw: u8,
    /// ECN-Echo
    #[deku(bits = "1")]
    pub ecn: u8,
    #[deku(bits = "1")]
    pub urgent: u8,
    #[deku(bits = "1")]
    pub ack: u8,
    #[deku(bits = "1")]
    pub push: u8,
    #[deku(bits = "1")]
    pub reset: u8,
    #[deku(bits = "1")]
    pub syn: u8,
    #[deku(bits = "1")]
    pub fin: u8,
}

impl Default for TcpFlags {
    fn default() -> Self {
        TcpFlags {
            reserved: 0,
            nonce: 0,
            crw: 0,
            ecn: 0,
            urgent: 0,
            ack: 0,
            push: 0,
            reset: 0,
            syn: 0,
            fin: 0,
        }
    }
}

impl core::fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}{}{}{}{}",
            if self.syn == 1 { "S" } else { "" },
            if self.push == 1 { "P" } else { "" },
            if self.ack == 1 { "A" } else { "" },
            if self.fin == 1 { "F" } else { "" },
            if self.reset == 1 { "R" } else { "" },
        )
    }
}

/**
TCP Header

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
*/
#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[allow(missing_docs)]
pub struct Tcp {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    /// size of tcp header in 32-bit words
    #[deku(bits = "4")]
    pub offset: u8,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgptr: u16,
    #[deku(reader = "Tcp::read_options(*offset, deku::rest)")]
    pub options: Vec<TcpOption>,
}

impl Tcp {
    fn read_options(
        offset: u8,
        rest: &BitSlice<Msb0, u8>,
    ) -> Result<(&BitSlice<Msb0, u8>, Vec<TcpOption>), DekuError> {
        let length = offset
            .checked_sub(5)
            .and_then(|v| v.checked_mul(4))
            .ok_or_else(|| DekuError::Parse("error: invalid tcp offset".to_string()))?;

        if length == 0 {
            return Ok((rest, Vec::new()));
        }

        // slice off length from rest
        let bits: usize = length as usize * 8;

        // Check split_at precondition
        if bits > rest.len() {
            return Err(DekuError::Parse(
                "not enough data to read tcp options".to_string(),
            ));
        }

        let (mut option_rest, rest) = rest.split_at(bits);

        let mut tcp_options = Vec::with_capacity(1); // at-least 1
        while !option_rest.is_empty() {
            let (option_rest_new, tcp_option) =
                TcpOption::read(option_rest, deku::ctx::Endian::Big)?;

            tcp_options.push(tcp_option);

            option_rest = option_rest_new;
        }

        Ok((rest, tcp_options))
    }
}

impl Default for Tcp {
    fn default() -> Self {
        Tcp {
            sport: 0,
            dport: 0,
            seq: 0,
            ack: 0,
            offset: 5,
            flags: TcpFlags::default(),
            window: 0,
            checksum: 0,
            urgptr: 0,
            options: Vec::new(),
        }
    }
}

/// Ipv6 pseudo header used in tcp checksum calculation
#[derive(Debug, PartialEq, Clone, DekuWrite)]
#[deku(endian = "big")]
struct Ipv6PseudoHeader {
    src: u128,
    dst: u128,
    length: u32,
    zeros: [u8; 3],
    next_header: IpProtocol,
}

impl Ipv6PseudoHeader {
    fn new(ipv6: &Ipv6, tcp_length: u32) -> Self {
        Ipv6PseudoHeader {
            src: ipv6.src,
            dst: ipv6.dst,
            length: tcp_length,
            zeros: [0; 3],
            next_header: ipv6.next_header,
        }
    }
}

/// Ipv4 pseudo header used in tcp checksum calculation
#[derive(Debug, PartialEq, Clone, DekuWrite)]
#[deku(endian = "big")]
struct Ipv4PseudoHeader {
    src: u32,
    dst: u32,
    zeros: u8,
    protocol: IpProtocol,
    length: u16,
}

impl Ipv4PseudoHeader {
    fn new(ipv4: &Ipv4, tcp_length: u16) -> Self {
        Ipv4PseudoHeader {
            src: ipv4.src,
            dst: ipv4.dst,
            zeros: 0,
            protocol: ipv4.protocol,
            length: tcp_length,
        }
    }
}

impl Layer for Tcp {}
impl LayerExt for Tcp {
    fn finalize(&mut self, prev: &[LayerOwned], next: &[LayerOwned]) -> Result<(), LayerError> {
        let tcp_header = {
            let data = LayerExt::to_bytes(self)?; // TODO: We could verify options length instead

            // align tcp header to 32-bit boundary for offset calculation
            let pad_amt = 4 * ((data.len() + 3) / 4) - data.len();
            for _ in 0..pad_amt {
                self.options.push(TcpOption::EOL);
            }

            let mut data = LayerExt::to_bytes(self)?;

            // Clear checksum bytes for calculation
            data[16] = 0x00;
            data[17] = 0x00;

            data
        };
        let tcp_header_len = tcp_header.len();

        // Update the tcp checksum
        if let Some(prev_layer) = prev.last() {
            let tcp_payload = crate::layer::utils::data_of_layers(next)?;

            // length of tcp header + tcp_payload
            let tcp_length = tcp_header_len
                .checked_add(tcp_payload.len())
                .ok_or_else(|| {
                    LayerError::Finalize(
                        "Overflow occured when calculating length for tcp (v4) checksum"
                            .to_string(),
                    )
                })?;

            let ip_pseudo_header = if let Some(ipv4) = get_layer!(prev_layer, Ipv4) {
                Some(
                    Ipv4PseudoHeader::new(
                        ipv4,
                        u16::try_from(tcp_length).map_err(|_e| {
                            LayerError::Finalize("Failed to convert tcp_length to u16".to_string())
                        })?,
                    )
                    .to_bytes()?,
                )
            } else if let Some(ipv6) = get_layer!(prev_layer, Ipv6) {
                Some(
                    Ipv6PseudoHeader::new(
                        ipv6,
                        u32::try_from(tcp_length).map_err(|_e| {
                            LayerError::Finalize("Failed to convert tcp_length to u32".to_string())
                        })?,
                    )
                    .to_bytes()?,
                )
            } else {
                None
            };

            if let Some(ip_pseudo_header) = ip_pseudo_header {
                let mut data = ip_pseudo_header;
                data.extend(tcp_header);
                data.extend(tcp_payload);

                self.checksum = super::ip::checksum(&data)
            }
        }

        debug_assert_eq!(
            0,
            tcp_header_len % 4,
            "dev error: tcp header should be aligned"
        );
        // Update offset
        self.offset = u8::try_from(tcp_header_len / 4)
            .map_err(|_e| LayerError::Finalize("Failed to convert tcp offset to u8".to_string()))?;

        Ok(())
    }

    fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    where
        Self: Sized,
    {
        let ((rest, bit_offset), tcp) = Tcp::from_bytes((input, 0))?;
        debug_assert_eq!(0, bit_offset);
        Ok((rest, tcp))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
        Ok(DekuContainerWrite::to_bytes(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{Layer, LayerError, LayerExt};
    use alloc::boxed::Box;
    use hexlit::hex;
    use rstest::*;
    use std::convert::TryFrom;

    macro_rules! declare_test_layer {
        ($name:ident, $size:tt) => {
            #[derive(Debug, Default)]
            struct $name {}
            #[allow(dead_code)]
            impl $name {
                fn new() -> Self {
                    Self {}
                }
                fn boxed() -> Box<dyn LayerExt> {
                    Box::new(Self {})
                }
            }
            impl Layer for $name {}
            impl LayerExt for $name {
                fn finalize(
                    &mut self,
                    _prev: &[LayerOwned],
                    _next: &[LayerOwned],
                ) -> Result<(), LayerError> {
                    unimplemented!()
                }

                fn parse(_input: &[u8]) -> Result<(&[u8], Self), LayerError>
                where
                    Self: Sized,
                {
                    unimplemented!()
                }

                fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
                    Ok([0u8; $size].to_vec())
                }
            }
        };
    }

    declare_test_layer!(Layer0, 0);
    declare_test_layer!(Layer100, 100);

    #[rstest(input, expected,
        case(
            &hex!("0d2c005038affe14114c618c501825bca9580000"),
            Tcp {
                sport: 3372,
                dport: 80,
                seq: 951057940,
                ack: 290218380,
                offset: 5,
                flags: TcpFlags { ack: 1, push: 1, ..TcpFlags::default()},
                window: 9660,
                checksum: 0xa958,
                urgptr: 0,
                options: Vec::new(),
            },
        ),
        case(
            &hex!("c213005086eebc64e4d6bb98b01000c49afc00000101080ad3845879407337de0101050ae4d6c0f0e4d6cba0"),
            Tcp {
                sport: 49683,
                dport: 80,
                seq: 2263792740,
                ack: 3839277976,
                offset: 11,
                flags: TcpFlags { ack: 1, ..TcpFlags::default()},
                window: 196,
                checksum: 0x9afc,
                urgptr: 0,
                options: vec![
                    TcpOption::NOP, TcpOption::NOP,
                    TcpOption::Timestamp {
                        length: 10,
                        value: TimestampData {
                            start: 3548665977,
                            end: 1081292766
                        }
                    },
                    TcpOption::NOP, TcpOption::NOP,
                    TcpOption::SAck {
                        length: 10,
                        value: vec![SAckData { begin: 3839279344, end: 3839282080 }]
                    },
                ]
            },
        ),
        #[should_panic(expected = "error: invalid tcp offset")]
        case(
            &hex!("0d2c005038affe14114c618c101825bca9580000"),
            Tcp::default(),
        ),
        #[should_panic(expected = "Parse(\"not enough data to read tcp options\")")]
        case(
            &hex!("ffffffffffffffffffffffffffffffffffffffff"),
            Tcp::default(),
        )
    )]
    fn test_tcp_rw(input: &[u8], expected: Tcp) {
        let ret_read = Tcp::try_from(input).unwrap();
        assert_eq!(expected, ret_read);

        let ret_write = LayerExt::to_bytes(&ret_read).unwrap();
        assert_eq!(input.to_vec(), ret_write);
    }

    #[test]
    fn test_tcp_default() {
        assert_eq!(
            Tcp {
                sport: 0,
                dport: 0,
                seq: 0,
                ack: 0,
                offset: 5,
                flags: TcpFlags::default(),
                window: 0,
                checksum: 0,
                urgptr: 0,
                options: Vec::new(),
            },
            Tcp::default()
        )
    }

    #[test]
    fn test_tcp_finalize_offset() {
        let mut tcp = Tcp::default();
        assert_eq!(5, tcp.offset);
        tcp.finalize(&[], &[]).unwrap();
        assert_eq!(5, tcp.offset);

        // Extend the tcp options by 32 bits
        tcp.options.push(TcpOption::NOP);
        tcp.options.push(TcpOption::NOP);
        tcp.options.push(TcpOption::NOP);
        tcp.options.push(TcpOption::NOP);

        tcp.finalize(&[], &[]).unwrap();
        assert_eq!(6, tcp.offset);
    }

    #[test]
    fn test_tcp_finalize_offset_unaligned() {
        let mut tcp = Tcp::default();
        assert!(tcp.options.is_empty());

        // Already aligned
        tcp.finalize(&[], &[]).unwrap();
        assert!(tcp.options.is_empty());

        // Extend the tcp options to be unaligned
        tcp.options.push(TcpOption::NOP);
        tcp.options.push(TcpOption::NOP);
        assert_eq!(vec![TcpOption::NOP; 2], tcp.options);

        tcp.finalize(&[], &[]).unwrap();

        // Verify that it's aligned with EOL
        assert_eq!(
            vec![
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::EOL,
                TcpOption::EOL
            ],
            tcp.options
        );
    }

    #[test]
    fn test_tcp_finalize_checksum_v4() {
        let expected_checksum = 0xB11A;

        let ipv4 = Box::new(Ipv4::default());

        let mut tcp = Tcp::default();

        tcp.finalize(
            &[ipv4],
            &[Layer100::boxed(), Layer0::boxed(), Layer100::boxed()],
        )
        .unwrap();

        assert_eq!(expected_checksum, tcp.checksum);
    }

    #[test]
    fn test_tcp_finalize_checksum_v6() {
        let expected_checksum = 0xB0E6;

        let ipv6 = Box::new(Ipv6::default());

        let mut tcp = Tcp::default();

        tcp.finalize(
            &[ipv6],
            &[Layer100::boxed(), Layer0::boxed(), Layer100::boxed()],
        )
        .unwrap();

        assert_eq!(expected_checksum, tcp.checksum);
    }

    #[test]
    fn test_tcp_finalize() {
        let mut tcp = Tcp::default();
        assert_eq!(0, tcp.checksum);
        assert_eq!(5, tcp.offset);

        tcp.options.push(TcpOption::NOP);
        let ipv4 = Box::new(Ipv4::default());
        tcp.finalize(&[ipv4], &[Layer100::boxed()]).unwrap();

        // Only these fields should change during a finalize
        let expected_tcp = Tcp {
            checksum: 0xB07A,
            offset: 6,
            options: vec![
                TcpOption::NOP,
                TcpOption::EOL,
                TcpOption::EOL,
                TcpOption::EOL,
            ],
            ..Default::default()
        };

        assert_eq!(expected_tcp, tcp);
    }
}
