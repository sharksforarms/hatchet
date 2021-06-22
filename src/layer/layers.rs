/*!
  Temporary layer module, this will be removed

  TODO: Split out into separate directories...
*/

use alloc::boxed::Box;

use crate::{
    get_layer,
    layer::{Layer, LayerBuilder, LayerError, LayerExt, LayerOwned},
};

#[derive(Debug, Default)]
/// Ether
pub struct Ether {}
/// EtherBuilder
pub struct EtherBuilder {}

impl LayerBuilder for EtherBuilder {
    fn parse<'a>(&self, input: &'a [u8]) -> Result<(&'a [u8], Box<dyn LayerExt>), LayerError> {
        let (rest, ether) = Ether::parse(input)?;
        Ok((rest, Box::new(ether)))
    }
}

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

/// Ipv4Builder
pub struct Ipv4Builder {}

impl LayerBuilder for Ipv4Builder {
    fn parse<'a>(&self, input: &'a [u8]) -> Result<(&'a [u8], Box<dyn LayerExt>), LayerError> {
        let (rest, ipv4) = Ipv4::parse(input)?;
        Ok((rest, Box::new(ipv4)))
    }
}

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
/// TcpBuilder
pub struct TcpBuilder {}

impl LayerBuilder for TcpBuilder {
    fn parse<'a>(&self, input: &'a [u8]) -> Result<(&'a [u8], Box<dyn LayerExt>), LayerError> {
        let (rest, tcp) = Tcp::parse(input)?;
        Ok((rest, Box::new(tcp)))
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
