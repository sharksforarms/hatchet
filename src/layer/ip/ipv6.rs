/*!
  Ipv6

  TODO: Ipv6 extension headers
*/

use super::IpProtocol;
use crate::layer::{Layer, LayerError, LayerExt, LayerOwned};
use alloc::{format, string::ToString, vec::Vec};
use core::convert::TryFrom;
use deku::prelude::*;

/**
IPv6 Header

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|     DS    |ECN|            Flow Label                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length        |  Next Header  |   Hop Limit     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                                 |
+                                                                 +
|                                                                 |
+                         Source Address                          +
|                                                                 |
+                                                                 +
|                                                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                                 |
+                                                                 +
|                                                                 |
+                      Destination Address                        +
|                                                                 |
+                                                                 +
|                                                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
*/
#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct Ipv6 {
    /// Version
    #[deku(bits = "4")]
    pub version: u8,
    /// Differentiated Services
    #[deku(bits = "6")]
    pub ds: u8,
    /// Explicit Congestion Notification
    #[deku(bits = "2")]
    pub ecn: u8,
    /// Flow Label
    #[deku(bits = "20")]
    pub label: u32,
    /// Payload Length
    pub length: u16,
    /// Next Header
    pub next_header: IpProtocol,
    /// Hop Limit
    pub hop_limit: u8,
    /// Source IP Address
    pub src: u128,
    /// Destination IP Address
    pub dst: u128,
}

impl Default for Ipv6 {
    fn default() -> Self {
        Ipv6 {
            version: 0,
            ds: 0,
            ecn: 0,
            label: 0,
            length: 0,
            next_header: IpProtocol::IPV6NONXT,
            hop_limit: 0,
            src: 0xff000000000000000000000000000000,
            dst: 0xff000000000000000000000000000000,
        }
    }
}

impl Layer for Ipv6 {}
impl LayerExt for Ipv6 {
    fn finalize(&mut self, _prev: &[LayerOwned], next: &[LayerOwned]) -> Result<(), LayerError> {
        // Update length field
        self.length =
            u16::try_from(crate::layer::utils::length_of_layers(next)?).map_err(|_e| {
                LayerError::Finalize("Could not convert layer length to u16".to_string())
            })?;

        // TODO: Update next header?
        Ok(())
    }

    fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    where
        Self: Sized,
    {
        let ((rest, bit_offset), ipv6) = Ipv6::from_bytes((input, 0))?;
        debug_assert_eq!(0, bit_offset);
        Ok((rest, ipv6))
    }

    fn to_vec(&self) -> Result<Vec<u8>, LayerError> {
        Ok(self.to_bytes()?)
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

                fn to_vec(&self) -> Result<Vec<u8>, LayerError> {
                    Ok([0u8; $size].to_vec())
                }
            }
        };
    }

    declare_test_layer!(Layer0, 0);
    declare_test_layer!(Layer100, 100);

    #[rstest(input, expected,
        case(
            &hex!("60000000012867403ffe802000000001026097fffe0769ea3ffe050100001c010200f8fffe03d9c0"),
            Ipv6 {
                version: 6,
                ds: 0,
                ecn: 0,
                label: 0,
                length: 296,
                next_header: IpProtocol::PIM,
                hop_limit: 64,
                src: 0x3ffe802000000001026097fffe0769ea,
                dst: 0x3ffe050100001c010200f8fffe03d9c0,
            }
        ),
    )]
    fn test_ipv6_rw(input: &[u8], expected: Ipv6) {
        let ipv6 = Ipv6::try_from(input).unwrap();
        assert_eq!(expected, ipv6);
    }

    #[test]
    fn test_ipv6_default() {
        assert_eq!(
            Ipv6 {
                version: 0,
                ds: 0,
                ecn: 0,
                label: 0,
                length: 0,
                next_header: IpProtocol::IPV6NONXT,
                hop_limit: 0,
                src: 0xff000000000000000000000000000000,
                dst: 0xff000000000000000000000000000000,
            },
            Ipv6::default(),
        );
    }

    #[rstest(expected_length, layers,
        case::none(0, &[]),
        case::empty(0, &[Layer0::boxed()]),
        case::empty(100, &[Layer100::boxed()]),
        case::empty(200, &[Layer100::boxed(), Layer0::boxed(), Layer100::boxed()]),
    )]
    fn test_ipv6_finalize_length(expected_length: u16, layers: &[LayerOwned]) {
        let mut ipv6 = Ipv6::default();
        assert_eq!(0, ipv6.length);

        // Finalize should update the length
        ipv6.finalize(&[], layers).unwrap();

        assert_eq!(expected_length, ipv6.length);
    }

    #[test]
    fn test_ipv6_finalize() {
        let mut ipv6 = Ipv6::default();
        assert_eq!(0, ipv6.length);

        ipv6.finalize(&[Layer100::boxed()], &[Layer100::boxed()])
            .unwrap();

        // Only these fields should change during a finalize
        let expected_ipv6 = Ipv6 {
            length: 100,
            ..Default::default()
        };
        assert_eq!(expected_ipv6, ipv6);
    }
}
