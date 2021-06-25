/*!
  Layer error
*/
use alloc::string::{String, ToString};
use deku::DekuError;

/// Error parsing or building a layer
#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum LayerError {
    /// Recoverable error when reading a layer, needs more data
    Incomplete(usize),
    /// Parsing error when reading a layer
    Parse(String),
}

impl From<DekuError> for LayerError {
    fn from(e: DekuError) -> Self {
        match e {
            DekuError::Incomplete(need) => LayerError::Incomplete(need.byte_size()),
            _ => LayerError::Parse(e.to_string()),
        }
    }
}
