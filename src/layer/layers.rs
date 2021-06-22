/*!
  Temporary layer module, this will be removed

  TODO: Split out into separate directories...
*/

use crate::{
    get_layer,
    layer::{Layer, LayerError, LayerExt, LayerOwned},
};

#[derive(Debug, Default)]
/// Ether
pub struct Ether {}

impl Layer for Ether {}

impl LayerExt for Ether {
    fn finalize(&mut self, _prev: &[LayerOwned], _next: &[LayerOwned]) -> Result<(), LayerError> {
        Ok(())
    }

    fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    where
        Self: Sized,
    {
        Ok((input, Ether {}))
    }
}

#[derive(Debug, Default)]
/// Ipv4
pub struct Ipv4 {}

impl Layer for Ipv4 {}

impl LayerExt for Ipv4 {
    fn finalize(&mut self, prev: &[LayerOwned], _next: &[LayerOwned]) -> Result<(), LayerError> {
        if let Some(prev_layer) = prev.last() {
            if let Some(_ether) = get_layer!(**prev_layer, &Ether) {}
        }

        Ok(())
    }

    fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    where
        Self: Sized,
    {
        Ok((input, Ipv4 {}))
    }
}

#[derive(Debug)]
/// Tcp
pub struct Tcp {
    /// source port
    pub sport: u8,
}

impl Default for Tcp {
    fn default() -> Self {
        Tcp { sport: 80 }
    }
}
impl Layer for Tcp {}

impl LayerExt for Tcp {
    fn finalize(&mut self, _prev: &[LayerOwned], _next: &[LayerOwned]) -> Result<(), LayerError> {
        Ok(())
    }

    fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    where
        Self: Sized,
    {
        let rest = input;
        Ok((rest, Tcp::default()))
    }
}
