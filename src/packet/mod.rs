/*!
  Packet parsing and construction
*/

use alloc::{boxed::Box, vec, vec::Vec};
use core::any::TypeId;
use hashbrown::HashMap;

use crate::{
    get_layer,
    layer::{LayerBuilder, LayerExt, LayerOwned, LayerRef},
};

pub mod error;
pub use error::PacketError;

/// Read-only view of a packet
pub struct PacketView<'a> {
    #[allow(dead_code)]
    layers: Vec<LayerRef<'a>>,
}

impl<'a> PacketView<'a> {
    /// Create a PacketView from layers
    pub fn from_layers(layers: Vec<LayerRef<'a>>) -> Self {
        Self { layers }
    }
}

/// A packet is simply a collection of [Layer](crate::layer::LayerExt)
#[derive(Debug)]
pub struct Packet {
    layers: Vec<LayerOwned>,
}

impl Packet {
    /// Construct a Packet given existing layers
    pub fn from_layers(layers: Vec<LayerOwned>) -> Self {
        Self { layers }
    }

    /// Finalize a packet
    ///
    /// This will call finalize on each layer of the packet
    pub fn finalize(&mut self) -> Result<(), PacketError> {
        for i in 0..self.layers.len() {
            let (prev, rest) = self.layers.split_at_mut(i);
            let (current, next) = rest.split_at_mut(1);

            let layer = current.first_mut().expect("dev error: should never panic");
            layer.finalize(prev, next)?;
        }

        Ok(())
    }

    /// Immutable access of the layers
    pub fn layers(&self) -> &[LayerOwned] {
        &self.layers
    }

    /// Mutable access of the layers
    pub fn layers_mut(&mut self) -> &mut [LayerOwned] {
        &mut self.layers
    }
}

type LayerBinding = Box<dyn Fn(&dyn LayerExt) -> Option<Box<dyn LayerBuilder>>>;

/**
Parse a [Packet](self::Packet) given layer binding rules

A layer binding specifies which [Layer](crate::layer::Layer) to read next,
given the current parsed layer.
*/
pub struct PacketBuilder {
    layer_bindings: HashMap<TypeId, Vec<LayerBinding>>,
}

impl PacketBuilder {
    /// Create a packet builder with default bindings
    // TODO: Add table/list of existing bindings, autogenerate somehow?
    pub fn new() -> Self {
        PacketBuilder::default()
    }

    /// Create a packet builder without any default bindings
    pub fn without_bindings() -> Self {
        PacketBuilder {
            layer_bindings: HashMap::new(),
        }
    }

    /**
    Add a layer binding to the packet builder

    This allows the definition of custom logic to help the parser determine the
    next layer.

    # Example

    ```rust
    # use rust_packet::{
    #   is_layer, get_layer,
    #   packet::PacketBuilder,
    #    layer::{Layer, LayerExt, LayerBuilder, LayerOwned, LayerError}
    # };
    # #[derive(Debug, PartialEq)]
    # enum EtherType {
    #    Ipv4 = 0x0800
    # }
    # #[derive(Debug)]
    # struct Ether {
    #    ether_type: EtherType
    # }
    # impl Layer for Ether {}
    # impl LayerExt for Ether {
    #     fn finalize(&mut self, prev: &[LayerOwned], _next: &[LayerOwned]) -> Result<(), LayerError> {
    #         unimplemented!();
    #     }
    #
    #     fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    #     where
    #         Self: Sized,
    #     {
    #         Ok((input, Ether { ether_type: EtherType::Ipv4 }))
    #     }
    # }
    # impl Layer for Ipv4 {}
    # impl LayerExt for Ipv4 {
    #     fn finalize(&mut self, prev: &[LayerOwned], _next: &[LayerOwned]) -> Result<(), LayerError> {
    #         unimplemented!();
    #     }
    #
    #     fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    #     where
    #         Self: Sized,
    #     {
    #         Ok((input, Ipv4 {}))
    #     }
    # }
    # #[derive(Debug)]
    # struct Ipv4 {}
    # struct Ipv4Builder {}
    # impl LayerBuilder for Ipv4Builder {
    #     fn parse<'a>(&self, input: &'a [u8]) -> Result<(&'a [u8], Box<dyn LayerExt>), LayerError> {
    #         let (rest, ipv4) = Ipv4::parse(input)?;
    #         Ok((rest, Box::new(ipv4)))
    #     }
    # }

    # fn main() {
        let mut packet_builder = PacketBuilder::without_bindings();

        packet_builder.bind_layer::<Ether, _>(|ether: &Ether| {
            match ether.ether_type {
                EtherType::Ipv4 => Some(Box::new(Ipv4Builder {})),
                // ...
                _ => None
            }
        });

    #   let input = b"input";
        let (rest, packet) = packet_builder.parse_packet::<Ether>(input).unwrap();

        let layers = packet.layers();
        assert_eq!(2, layers.len());
        assert!(is_layer!(layers[0], Ether));
        assert!(is_layer!(layers[1], Ipv4));
    # }
    ```
    */
    pub fn bind_layer<From: LayerExt + 'static, F>(&mut self, f: F)
    where
        F: 'static + Fn(&From) -> Option<Box<dyn LayerBuilder>>,
    {
        let tid = TypeId::of::<From>();
        let bindings = self.layer_bindings.entry(tid).or_insert_with(Vec::new);
        (*bindings).push(Box::new(move |current_layer: &dyn LayerExt| -> _ {
            // SAFETY: This callback is only to be called if the layer type is `From` therefor we
            // can safely unwrap here.
            let l = get_layer!(current_layer, From).expect("dev error: This is always Some");
            f(l)
        }));
    }

    /// Parse a packet from bytes, returning the un-parsed data
    pub fn parse_packet<'a, T: LayerExt + 'static>(
        &self,
        input: &'a [u8],
    ) -> Result<(&'a [u8], Packet), PacketError> {
        let mut layers = vec![];

        let (mut rest, layer) = T::parse(input)?;

        let mut current_layer: Box<dyn LayerExt> = Box::new(layer);

        // Given the currently parsed layer:
        //  - Lookup the layer bindings for the current layer
        //  - Find the next layer builder by executing the bindings
        //      - bindings are executed in reverse sequence
        //      - if a binding returns a builder, it returns with that builder.
        //        (this is to allow users to override some behaviour)
        //  - Parse the next layer with the builder
        //  - Next layer becomes current layer, loop
        loop {
            let tid = current_layer.as_any().type_id();
            let callbacks = self.layer_bindings.get(&tid);

            // Using the layer bindings, find the builder for the next layer
            let next_layer_builder = if let Some(callbacks) = callbacks {
                // labelled loop used here to break out early from for loop
                #[allow(clippy::never_loop)]
                'lbl: loop {
                    // start from last inserted
                    for cb in callbacks.iter().rev() {
                        let builder = cb(current_layer.as_ref());

                        if builder.is_some() {
                            break 'lbl builder;
                        }
                    }

                    break None;
                }
            } else {
                None
            };

            // Next layer becomes the current layer
            if let Some(next_layer_builder) = next_layer_builder {
                let (new_rest, next_layer) = next_layer_builder.parse(rest)?;
                rest = new_rest;

                layers.push(current_layer);
                current_layer = next_layer;
            } else {
                break;
            }
        }

        layers.push(current_layer);

        Ok((rest, Packet::from_layers(layers)))
    }
}

impl Default for PacketBuilder {
    fn default() -> Self {
        // TODO: Add default layer bindings here? Ether -> Ip... etc
        PacketBuilder {
            layer_bindings: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        get_layer,
        layer::{Layer, LayerError, LayerExt},
    };

    macro_rules! declare_test_layer {
        ($name:ident, $builder:ident) => {
            #[derive(Debug)]
            struct $name {}
            #[allow(dead_code)]
            impl $name {
                fn new() -> Self {
                    Self {}
                }
            }
            impl Layer for $name {}
            impl LayerExt for $name {
                fn finalize(
                    &mut self,
                    _prev: &[LayerOwned],
                    _next: &[LayerOwned],
                ) -> Result<(), LayerError> {
                    Ok(())
                }

                fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
                where
                    Self: Sized,
                {
                    Ok((input, Self {}))
                }
            }

            struct $builder {}
            impl LayerBuilder for $builder {
                fn parse<'a>(
                    &self,
                    input: &'a [u8],
                ) -> Result<(&'a [u8], Box<dyn LayerExt>), LayerError> {
                    let (rest, layer) = $name::parse(input)?;
                    Ok((rest, Box::new(layer)))
                }
            }
        };
    }

    declare_test_layer!(Layer0, Layer0Builder);
    declare_test_layer!(Layer1, Layer1Builder);
    declare_test_layer!(Layer2, Layer2Builder);

    #[test]
    fn test_packet_view_from_layers() {
        let layer0 = Layer0::new();
        let layer1 = Layer1::new();

        let layers: Vec<LayerRef> = vec![&layer0, &layer1];
        let packet = PacketView::from_layers(layers);
        assert_eq!(2, packet.layers.len());
    }

    #[test]
    fn test_packet_owned_from_layers() {
        let layer0 = Box::new(Layer0::new());
        let layer1 = Box::new(Layer1::new());

        let layers: Vec<LayerOwned> = vec![layer0, layer1];
        let packet = Packet::from_layers(layers);
        assert_eq!(2, packet.layers.len());
    }

    #[test]
    fn test_packet_finalize_lengths() {
        // test a range on lengths for the packet finalize function
        for i in 0..5 {
            let layers: Vec<LayerOwned> = (0..i)
                .map(|_| Box::new(Layer0::new()) as LayerOwned)
                .collect();
            let mut packet = Packet::from_layers(layers);
            packet.finalize().unwrap();
        }
    }

    #[test]
    fn test_packet_finalize() {
        #[derive(Debug, PartialEq, Clone)]
        struct TestLayer {
            count: u8,                // count increases every time the layer is finalized
            expected_num_prev: usize, // expected number of previous layers when finalized is called
            expected_num_next: usize, // expected number of next layers when finalized is called
        }

        impl TestLayer {
            fn new(expected_num_prev: usize, expected_num_next: usize) -> Self {
                Self {
                    count: 0,
                    expected_num_prev,
                    expected_num_next,
                }
            }
        }

        impl Layer for TestLayer {}
        impl LayerExt for TestLayer {
            fn finalize(
                &mut self,
                prev: &[LayerOwned],
                next: &[LayerOwned],
            ) -> Result<(), LayerError> {
                assert_eq!(self.expected_num_prev, prev.len());
                assert_eq!(self.expected_num_next, next.len());
                self.count += 1;
                Ok(())
            }

            fn parse(_input: &[u8]) -> Result<(&[u8], Self), LayerError>
            where
                Self: Sized,
            {
                unimplemented!()
            }
        }

        let layers: Vec<LayerOwned> = vec![
            Box::new(TestLayer::new(0, 2)),
            Box::new(TestLayer::new(1, 1)),
            Box::new(TestLayer::new(2, 0)),
        ];
        let mut packet = Packet::from_layers(layers);
        packet.finalize().unwrap();

        // Get layers back as `TestLayer`
        let test_layers: Vec<_> = packet
            .layers
            .iter()
            .map(|v| get_layer!(v, TestLayer).unwrap())
            .collect();

        assert_eq!(3, test_layers.len());
        for layer in test_layers {
            assert_eq!(1, layer.count);
        }
    }

    #[test]
    fn test_packet_builder_bind_layer() {
        let mut pb = PacketBuilder::without_bindings();
        assert_eq!(0, pb.layer_bindings.len());

        pb.bind_layer::<Layer0, _>(|_from| Some(Box::new(Layer1Builder {})));
        assert_eq!(1, pb.layer_bindings.len());
        assert_eq!(
            1,
            pb.layer_bindings
                .get(&TypeId::of::<Layer0>())
                .unwrap()
                .len()
        );

        pb.bind_layer::<Layer0, _>(|_from| Some(Box::new(Layer1Builder {})));
        assert_eq!(1, pb.layer_bindings.len());
        assert_eq!(
            2,
            pb.layer_bindings
                .get(&TypeId::of::<Layer0>())
                .unwrap()
                .len()
        );
    }

    #[test]
    fn test_packet_builder_none() {
        let mut pb = PacketBuilder::without_bindings();
        assert_eq!(0, pb.layer_bindings.len());

        {
            pb.bind_layer::<Layer0, _>(|_from| None);

            let (_rest, packet) = pb.parse_packet::<Layer0>(b"testdata").unwrap();
            assert_eq!(1, packet.layers.len());
            assert!(get_layer!(packet.layers[0], Layer0).is_some());
        }

        {
            pb.bind_layer::<Layer0, _>(|_from| Some(Box::new(Layer1Builder {})));

            let (_rest, packet) = pb.parse_packet::<Layer0>(b"testdata").unwrap();
            assert_eq!(2, packet.layers.len());
            assert!(get_layer!(packet.layers[0], Layer0).is_some());
            assert!(get_layer!(packet.layers[1], Layer1).is_some());
        }
    }
    #[test]
    fn test_packet_parse_packet_binding_order() {
        let mut pb = PacketBuilder::without_bindings();
        assert_eq!(0, pb.layer_bindings.len());

        {
            pb.bind_layer::<Layer0, _>(|_from| Some(Box::new(Layer1Builder {})));

            let (_rest, packet) = pb.parse_packet::<Layer0>(b"testdata").unwrap();
            assert_eq!(2, packet.layers.len());
            assert!(get_layer!(packet.layers[0], Layer0).is_some());
            assert!(get_layer!(packet.layers[1], Layer1).is_some());
        }

        {
            pb.bind_layer::<Layer0, _>(|_from| Some(Box::new(Layer2Builder {})));

            let (_rest, packet) = pb.parse_packet::<Layer0>(b"testdata").unwrap();
            assert_eq!(2, packet.layers.len());
            assert!(get_layer!(packet.layers[0], Layer0).is_some());
            assert!(get_layer!(packet.layers[1], Layer2).is_some());
        }
    }
}
