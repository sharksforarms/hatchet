/*!
Module to send and receive packets over an interface
*/

#[cfg(feature = "pcap")]
pub mod pcap;

#[cfg(feature = "pcap")]
pub mod pcapfile;

#[cfg(feature = "pnet")]
pub mod pnet;

pub mod error;

use crate::datalink::error::DataLinkError;
use crate::packet::{Packet, PacketBuilder};

/// A generic Packet interface used to Read and Write packets
pub struct Interface<T: PacketRead + PacketWrite>(pub T);

impl<T: PacketRead + PacketWrite> Iterator for Interface<T> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        let packet = self.0.read();
        if let Ok(packet) = packet {
            Some(packet)
        } else {
            None
        }
    }
}

impl<T: PacketRead + PacketWrite> PacketInterface for Interface<T> {
    fn init(name: &str) -> Result<Self, DataLinkError>
    where
        Self: Sized,
    {
        Ok(Interface(T::init(name)?))
    }

    fn init_with_builder(name: &str, packet_builder: PacketBuilder) -> Result<Self, DataLinkError>
    where
        Self: Sized,
    {
        Ok(Interface(T::init_with_builder(name, packet_builder)?))
    }
}

impl<T: PacketRead + PacketWrite> PacketWrite for Interface<T> {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        self.0.write(packet)
    }
}

/// Packet interface
pub trait PacketInterface {
    /// Initialization of an interface
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init(name: &str) -> Result<Self, DataLinkError>
    where
        Self: Sized;

    /// Initialization of an interface with a packet builder
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init_with_builder(name: &str, packet_builder: PacketBuilder) -> Result<Self, DataLinkError>
    where
        Self: Sized;
}

/// Packet read on an interface
pub trait PacketRead: PacketInterface {
    /// Read packet
    fn read(&mut self) -> Result<Packet, DataLinkError>;
}

/// Packet write on an interface
pub trait PacketWrite: PacketInterface {
    /// Write packet
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError>;
}
