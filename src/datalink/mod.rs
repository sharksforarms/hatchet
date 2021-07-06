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
pub struct Interface<Rx: PacketRead, Tx: PacketWrite> {
    rx: Rx,
    tx: Tx,
}

impl<Rx: PacketRead, Tx: PacketWrite> Interface<Rx, Tx> {
    /// Initialize read/write interface
    pub fn init<T: PacketInterface<Rx = Rx, Tx = Tx>>(
        name: &str,
    ) -> Result<Interface<T::Rx, T::Tx>, DataLinkError>
    where
        Self: Sized,
    {
        T::init(name)
    }

    /// Initialize read/write interface with a custom builder
    pub fn init_with_builder<T: PacketInterface>(
        name: &str,
        packet_builder: PacketBuilder,
    ) -> Result<Interface<T::Rx, T::Tx>, DataLinkError>
    where
        Self: Sized,
    {
        T::init_with_builder(name, packet_builder)
    }
}

impl<Rx: PacketRead, Tx: PacketWrite> Iterator for Interface<Rx, Tx> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        let packet = self.rx.read();
        if let Ok(packet) = packet {
            Some(packet)
        } else {
            None
        }
    }
}

impl<Rx: PacketRead, Tx: PacketWrite> PacketWrite for Interface<Rx, Tx> {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        self.tx.write(packet)
    }
}

impl<Rx: PacketRead, Tx: PacketWrite> PacketRead for Interface<Rx, Tx> {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        self.rx.read()
    }
}

/// Read + Write packet interface
pub trait PacketInterface {
    /// Packet reader
    type Rx: PacketRead;
    /// Packet writer
    type Tx: PacketWrite;

    /// Initialization of an interface
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init(name: &str) -> Result<Interface<Self::Rx, Self::Tx>, DataLinkError>
    where
        Self: Sized;

    /// Initialization of an interface with a packet builder
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init_with_builder(
        name: &str,
        packet_builder: PacketBuilder,
    ) -> Result<Interface<Self::Rx, Self::Tx>, DataLinkError>
    where
        Self: Sized;
}

/// Read-only packet interface
pub trait PacketInterfaceRead {
    /// Packet reader
    type Rx: PacketRead;

    /// Initialization of an interface
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init(name: &str) -> Result<InterfaceRx<Self::Rx>, DataLinkError>
    where
        Self: Sized;

    /// Initialization of an interface with a packet builder
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init_with_builder(
        name: &str,
        packet_builder: PacketBuilder,
    ) -> Result<InterfaceRx<Self::Rx>, DataLinkError>
    where
        Self: Sized;
}

/// Write-only packet interface
pub trait PacketInterfaceWrite {
    /// Packet writer
    type Tx: PacketWrite;

    /// Initialization of an interface
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init(name: &str) -> Result<InterfaceTx<Self::Tx>, DataLinkError>
    where
        Self: Sized;
}

/// Packet read on an interface
pub trait PacketRead {
    /// Read packet
    fn read(&mut self) -> Result<Packet, DataLinkError>;
}

/// Packet write on an interface
pub trait PacketWrite {
    /// Write packet
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError>;
}

/// Unimplemented packet writer
pub struct UnimplementedTx;
impl PacketWrite for UnimplementedTx {
    fn write(&mut self, _packet: Packet) -> Result<(), DataLinkError> {
        unimplemented!()
    }
}
/// Unimplemented packet reader
pub struct UnimplementedRx;
impl PacketRead for UnimplementedRx {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        unimplemented!()
    }
}

/// Reference to read-only interface
pub struct InterfaceRxRef<'a, T>
where
    T: PacketRead,
{
    rx: &'a mut T,
}

/// Reference to write-only interface
pub struct InterfaceTxRef<'a, T>
where
    T: PacketWrite,
{
    tx: &'a mut T,
}

/// Read-only interface
pub struct InterfaceRx<Rx>
where
    Rx: PacketRead,
{
    rx: Rx,
}

impl<Rx> InterfaceRx<Rx>
where
    Rx: PacketRead,
{
    /// Initialize read-only interface
    pub fn init<T: PacketInterfaceRead<Rx = Rx>>(
        name: &str,
    ) -> Result<InterfaceRx<T::Rx>, DataLinkError>
    where
        Self: Sized,
    {
        T::init(name)
    }

    /// Initialize read-only interface with custom builder
    pub fn init_with_builder<T: PacketInterfaceRead<Rx = Rx>>(
        name: &str,
        packet_builder: PacketBuilder,
    ) -> Result<InterfaceRx<T::Rx>, DataLinkError>
    where
        Self: Sized,
    {
        T::init_with_builder(name, packet_builder)
    }
}

/// Write-only interface
pub struct InterfaceTx<Tx>
where
    Tx: PacketWrite,
{
    tx: Tx,
}

impl<Tx> InterfaceTx<Tx>
where
    Tx: PacketWrite,
{
    /// Initialize write-only interface
    pub fn init<T: PacketInterfaceWrite<Tx = Tx>>(
        name: &str,
    ) -> Result<InterfaceTx<T::Tx>, DataLinkError>
    where
        Self: Sized,
    {
        T::init(name)
    }
}

impl<'a, T: PacketRead> PacketRead for InterfaceRxRef<'a, T> {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        self.rx.read()
    }
}

impl<T: PacketRead> PacketRead for InterfaceRx<T> {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        self.rx.read()
    }
}

impl<'a, T: PacketWrite> PacketWrite for InterfaceTxRef<'a, T> {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        self.tx.write(packet)
    }
}

impl<T: PacketWrite> PacketWrite for InterfaceTx<T> {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        self.tx.write(packet)
    }
}

impl<T: PacketRead> Iterator for InterfaceRxRef<'_, T> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        let packet = self.rx.read();
        if let Ok(packet) = packet {
            Some(packet)
        } else {
            None
        }
    }
}

impl<T: PacketRead> Iterator for InterfaceRx<T> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        let packet = self.rx.read();
        if let Ok(packet) = packet {
            Some(packet)
        } else {
            None
        }
    }
}

/// Split an interface into a reader and a writer interface
pub trait PacketInterfaceSplit: PacketRead + PacketWrite {
    /// Packet reader
    type Rx: PacketRead;
    /// Packet writer
    type Tx: PacketWrite;

    /// Split interface into referenced read and write interfaces
    fn split(&mut self) -> (InterfaceRxRef<'_, Self::Rx>, InterfaceTxRef<'_, Self::Tx>);

    /// Split interface into owned read and write interfaces
    fn into_split(self) -> (InterfaceRx<Self::Rx>, InterfaceTx<Self::Tx>);
}

impl<Rx: PacketRead, Tx: PacketWrite> PacketInterfaceSplit for Interface<Rx, Tx> {
    type Rx = Rx;
    type Tx = Tx;

    fn split(&mut self) -> (InterfaceRxRef<'_, Self::Rx>, InterfaceTxRef<'_, Self::Tx>) {
        (
            InterfaceRxRef { rx: &mut self.rx },
            InterfaceTxRef { tx: &mut self.tx },
        )
    }

    fn into_split(self) -> (InterfaceRx<Self::Rx>, InterfaceTx<Self::Tx>) {
        (InterfaceRx { rx: self.rx }, InterfaceTx { tx: self.tx })
    }
}
