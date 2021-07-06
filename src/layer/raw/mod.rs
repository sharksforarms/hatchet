/*!
Raw layer

A Raw layer represents un-parsed data or application data such as a UDP payload
*/
use alloc::{format, vec::Vec};
use deku::bitvec::{BitSlice, Msb0};
use deku::prelude::*;

use crate::layer::{Layer, LayerError, LayerExt, LayerOwned};

/// Raw layer
#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[allow(missing_docs)]
pub struct Raw {
    #[deku(reader = "Raw::reader(deku::rest)")]
    pub data: Vec<u8>,
    #[deku(skip)]
    pub bit_offset: usize,
}

impl Raw {
    fn reader(rest: &BitSlice<Msb0, u8>) -> Result<(&BitSlice<Msb0, u8>, Vec<u8>), DekuError> {
        // read all the rest
        let ret = rest.as_raw_slice().to_vec();
        let (empty, _rest) = rest.split_at(0);
        Ok((empty, ret))
    }
}

impl Default for Raw {
    fn default() -> Self {
        Raw {
            data: Vec::new(),
            bit_offset: 0,
        }
    }
}

impl Layer for Raw {}
impl LayerExt for Raw {
    fn finalize(&mut self, _prev: &[LayerOwned], _next: &[LayerOwned]) -> Result<(), LayerError> {
        Ok(())
    }

    fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    where
        Self: Sized,
    {
        let ((rest, bit_offset), raw) = Raw::from_bytes((input, 0))?;
        debug_assert_eq!(0, bit_offset);
        debug_assert_eq!(0, rest.len());
        Ok((rest, raw))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
        Ok(DekuContainerWrite::to_bytes(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_write() {
        let input = [0xAAu8, 0xBB];
        let layer = Raw {
            data: input.to_vec(),
            bit_offset: 0xFF,
        };
        let ret_write = LayerExt::to_bytes(&layer).unwrap();
        assert_eq!(input.to_vec(), ret_write);
    }

    #[test]
    fn test_raw_read() {
        let input = [0xAAu8, 0xBB];
        let (rest, layer) = Raw::from_bytes((input.as_ref(), 0)).unwrap();

        assert_eq!(
            Raw {
                data: input.to_vec(),
                bit_offset: 0,
            },
            layer
        );

        assert_eq!((0, 0), (rest.0.len(), rest.1));
    }

    #[test]
    fn test_raw_default() {
        assert_eq!(
            Raw {
                data: vec![],
                bit_offset: 0,
            },
            Raw::default()
        )
    }
}
