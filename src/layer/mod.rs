/*!
Packet layers

A layer can be represented by the [Layer](self::Layer) and [LayerExt](self::LayerExt)
traits.

*/
use alloc::boxed::Box;
use core::any::Any;

pub mod error;
pub mod layers;
pub use error::LayerError;

#[doc(hidden)]
pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A layer represents a section in the [Packet](crate::packet::Packet) or [PacketView](crate::packet::PacketView)
///
/// Any is used in order to retreive the original layer type, see [get_layer! macro](crate::get_layer)
pub trait Layer: AsAny {}

/// Layer construction functions for a [Packet](crate::packet::Packet)
pub trait LayerExt: core::fmt::Debug + Layer {
    /// Finalize a layer in relation to previous and next layers
    ///
    /// This should be used to update inter-dependant fields such as
    /// checksums, lengths, etc.
    fn finalize(&mut self, prev: &[LayerOwned], next: &[LayerOwned]) -> Result<(), LayerError>;

    fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    where
        Self: Sized;
}

pub trait LayerBuilder {
    fn parse<'a>(&self, input: &'a [u8]) -> Result<(&'a [u8], Box<dyn LayerExt>), LayerError>;
}

pub type LayerRef<'a> = &'a dyn Layer;
pub type LayerOwned = Box<dyn LayerExt>;

#[macro_export]
macro_rules! get_layer {
    ($layer:expr, $layer_ty:ty) => {
        $layer.as_any().downcast_ref::<$layer_ty>()
    };
}

#[macro_export]
macro_rules! is_layer {
    ($layer:expr, $layer_ty:ty) => {
        get_layer!($layer, $layer_ty).is_some()
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestLayer {}
    impl Layer for TestLayer {}

    struct TestLayerOther {}
    impl Layer for TestLayerOther {}

    #[test]
    fn test_get_layer_macro() {
        let layer: &dyn Layer = &TestLayer {};
        assert!(get_layer!(layer, TestLayer).is_some());
        assert!(get_layer!(layer, TestLayerOther).is_none());
    }

    #[test]
    fn test_is_layer_macro() {
        let layer: &dyn Layer = &TestLayer {};
        assert!(is_layer!(layer, TestLayer));
        assert!(!is_layer!(layer, TestLayerOther));
    }
}
