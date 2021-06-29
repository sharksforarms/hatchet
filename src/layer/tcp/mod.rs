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
        offset: u8, // tcp offset header field
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
            offset: 0,
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
        // Update the tcp checksum
        if let Some(prev_layer) = prev.last() {
            let tcp_header = {
                let mut data = self.to_bytes()?;

                // Clear checksum bytes for calculation
                data[16] = 0x00;
                data[17] = 0x00;

                data
            };
            let tcp_payload = crate::layer::utils::data_of_layers(next)?;

            // length of tcp header + tcp_payload
            let tcp_length = tcp_header
                .len()
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

        // TODO: Update offset
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

    fn to_vec(&self) -> Result<Vec<u8>, LayerError> {
        Ok(self.to_bytes()?)
    }
}

#[cfg(test)]
mod tests {
    use crate::layer::raw::Raw;

    use super::*;
    use alloc::boxed::Box;
    use hexlit::hex;
    use rstest::*;
    use std::convert::TryFrom;

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

        let ret_write = ret_read.to_bytes().unwrap();
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
                offset: 0,
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
    fn test_tcp_finalize_checksum_v4() {
        let expected_checksum = 0xa958;

        let ipv4 = Box::new(
            Ipv4::try_from(hex!("450002070f4540008006901091fea0ed41d0e4df").as_ref()).unwrap(),
        );

        let mut tcp =
            Tcp::try_from(hex!("0d2c005038affe14114c618c501825bc AAAA 0000").as_ref()).unwrap();

        let raw = Box::new(Raw::try_from(hex!("474554202f646f776e6c6f61642e68746d6c20485454502f312e310d0a486f73743a207777772e657468657265616c2e636f6d0d0a557365722d4167656e743a204d6f7a696c6c612f352e30202857696e646f77733b20553b2057696e646f7773204e5420352e313b20656e2d55533b2072763a312e3629204765636b6f2f32303034303131330d0a4163636570743a20746578742f786d6c2c6170706c69636174696f6e2f786d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c746578742f68746d6c3b713d302e392c746578742f706c61696e3b713d302e382c696d6167652f706e672c696d6167652f6a7065672c696d6167652f6769663b713d302e322c2a2f2a3b713d302e310d0a4163636570742d4c616e67756167653a20656e2d75732c656e3b713d302e350d0a4163636570742d456e636f64696e673a20677a69702c6465666c6174650d0a4163636570742d436861727365743a2049534f2d383835392d312c7574662d383b713d302e372c2a3b713d302e370d0a4b6565702d416c6976653a203330300d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a526566657265723a20687474703a2f2f7777772e657468657265616c2e636f6d2f646576656c6f706d656e742e68746d6c0d0a0d0a").as_ref()).unwrap());

        tcp.finalize(&[ipv4], &[raw]).unwrap();

        assert_eq!(expected_checksum, tcp.checksum);
    }

    #[test]
    fn test_tcp_finalize_checksum_v6() {
        let expected_checksum = 0x0e91;

        let ipv6 = Box::new(
            Ipv6::try_from(
                hex!(
                "6000000000240680200251834383000000000000518343832001063809020001020102fffee27596"
            )
                .as_ref(),
            )
            .unwrap(),
        );

        let mut tcp =
            Tcp::try_from(hex!("04020015626bf2f8e537a573501842640e910000").as_ref()).unwrap();

        let raw =
            Box::new(Raw::try_from(hex!("5553455220616e6f6e796d6f75730d0a").as_ref()).unwrap());

        tcp.finalize(&[ipv6], &[raw]).unwrap();

        assert_eq!(expected_checksum, tcp.checksum);
    }
}