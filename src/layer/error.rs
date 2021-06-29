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
    /// Error during finalization
    Finalize(String),
    /// Deku Error
    DekuError(String),
}

impl From<DekuError> for LayerError {
    fn from(e: DekuError) -> Self {
        match e {
            DekuError::Incomplete(need) => LayerError::Incomplete(need.byte_size()),
            DekuError::Parse(_) => LayerError::Parse(e.to_string()),
            _ => LayerError::DekuError(e.to_string()),
        }
    }
}
