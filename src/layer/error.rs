use alloc::string::String;

#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum LayerError {
    /// Recoverable error when reading a layer, needs more data
    Incomplete(usize),
    /// Parsing error when reading a layer
    Parse(String),
}
