/*!
Layer parsing and construction

A layer is represented by the [Layer](self::Layer) and [LayerExt](self::LayerExt)
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

/// Represents a section of a packet
///
/// Any is used in order to retrieve the original layer type, see [get_layer!](crate::get_layer) macro
pub trait Layer: AsAny {}

/// Extension of a layer to allow parsing and construction of a layer
pub trait LayerExt: core::fmt::Debug + Layer {
    /// Finalize a layer in relation to previous and next layers
    ///
    /// This should be used to update inter-dependant fields such as
    /// checksums, lengths, etc.
    fn finalize(&mut self, prev: &[LayerOwned], next: &[LayerOwned]) -> Result<(), LayerError>;

    /// Parse a layer from bytes
    ///
    /// Returns the remaining un-parsed data and a Layer
    fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    where
        Self: Sized;
}

/// Construct a layer
pub trait LayerBuilder {
    /// Parse a layer from bytes
    ///
    /// Returns the remaining un-parsed data and a Layer
    fn parse<'a>(&self, input: &'a [u8]) -> Result<(&'a [u8], Box<dyn LayerExt>), LayerError>;
}

/// A reference to a [Layer](self::Layer)
pub type LayerRef<'a> = &'a dyn Layer;

/// A boxed [LayerExt](self::LayerExt)
pub type LayerOwned = Box<dyn LayerExt>;

/**
Retrieve original type from a layer

Example

```rust
# use rust_packet::layer::Layer;
# use rust_packet::get_layer;
# struct Ether {}
# impl Ether {
#    pub fn new() -> Self {
#        Ether {}
#    }
# }
# impl Layer for Ether {}
# struct Ipv4 {}
# impl Layer for Ipv4 {}
let layer: &dyn Layer = &Ether::new();
assert!(get_layer!(layer, Ether).is_some());
assert!(get_layer!(layer, Ipv4).is_none());
```
*/
#[macro_export]
macro_rules! get_layer {
    ($layer:expr, $layer_ty:ty) => {
        $layer.as_any().downcast_ref::<$layer_ty>()
    };
}

/**
Test if a layer is of a certain type

Example

```rust
# use rust_packet::layer::Layer;
# use rust_packet::is_layer;
# struct Ether {}
# impl Ether {
#    pub fn new() -> Self {
#        Ether {}
#    }
# }
# impl Layer for Ether {}
# struct Ipv4 {}
# impl Layer for Ipv4 {}
let layer: &dyn Layer = &Ether::new();
assert!(is_layer!(layer, Ether));
assert!(!is_layer!(layer, Ipv4));
```
*/
#[macro_export]
macro_rules! is_layer {
    ($layer:expr, $layer_ty:ty) => {
        $layer.as_any().is::<$layer_ty>()
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
