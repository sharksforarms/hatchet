/*!
  Datalink error
*/
use crate::packet::PacketError;

/// Data link errors
#[derive(Debug)]
pub enum DataLinkError {
    /// Error during packet reading or writing
    PacketError(PacketError),
    /// Interface not found
    InterfaceNotFound,
    /// Unhandled interface type
    UnhandledInterfaceType,
    /// IO Error
    #[cfg(feature = "std")]
    IoError(std::io::Error),
    /// Error writing to interface buffer
    BufferError,
}

impl From<PacketError> for DataLinkError {
    fn from(e: PacketError) -> Self {
        DataLinkError::PacketError(e)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for DataLinkError {
    fn from(e: std::io::Error) -> Self {
        DataLinkError::IoError(e)
    }
}

//impl core::fmt::Display for DataLinkError {
//fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
//match *self {
//DataLinkError::PacketError(ref err) => write!(f, "Packet error: {}", err),
//DataLinkError::InterfaceNotFound => write!(f, "Interface not found"),
//DataLinkError::UnhandledInterfaceType => write!(f, "Unhandled interface type"),
//DataLinkError::IoError(ref err) => write!(f, "IO error: {}", err),
//DataLinkError::BufferError => write!(f, "Buffer error"),
//}
//}
//}

//#[cfg(feature = "std")]
//impl std::error::Error for DataLinkError {
//fn cause(&self) -> Option<&dyn std::error::Error> {
//Some(self)
//}
//}
