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
pub struct Interface<R: PacketRead, W: PacketWrite> {
    reader: R,
    writer: W,
}

impl<R: PacketRead, W: PacketWrite> Interface<R, W> {
    /// Initialize read/write interface
    pub fn init<T: PacketInterface<Reader = R, Writer = W>>(
        name: &str,
    ) -> Result<Interface<T::Reader, T::Writer>, DataLinkError>
    where
        Self: Sized,
    {
        T::init(name)
    }

    /// Initialize read/write interface with a custom builder
    pub fn init_with_builder<T: PacketInterface>(
        name: &str,
        packet_builder: PacketBuilder,
    ) -> Result<Interface<T::Reader, T::Writer>, DataLinkError>
    where
        Self: Sized,
    {
        T::init_with_builder(name, packet_builder)
    }

    /// Split interface into referenced read and write interfaces
    pub fn split(&mut self) -> (InterfaceReaderRef<'_, R>, InterfaceWriterRef<'_, W>) {
        (
            InterfaceReaderRef {
                reader: &mut self.reader,
            },
            InterfaceWriterRef {
                writer: &mut self.writer,
            },
        )
    }

    /// Split interface into owned read and write interfaces
    pub fn into_split(self) -> (InterfaceReader<R>, InterfaceWriter<W>) {
        (
            InterfaceReader {
                reader: self.reader,
            },
            InterfaceWriter {
                writer: self.writer,
            },
        )
    }
}

impl<R: PacketRead, W: PacketWrite> PacketWrite for Interface<R, W> {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        self.writer.write(packet)
    }
}

impl<R: PacketRead, W: PacketWrite> PacketRead for Interface<R, W> {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        self.reader.read()
    }
}

/// Read + Write packet interface
pub trait PacketInterface {
    /// Packet reader
    type Reader: PacketRead;
    /// Packet writer
    type Writer: PacketWrite;

    /// Initialization of an interface
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init(name: &str) -> Result<Interface<Self::Reader, Self::Writer>, DataLinkError>
    where
        Self: Sized;

    /// Initialization of an interface with a packet builder
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init_with_builder(
        name: &str,
        packet_builder: PacketBuilder,
    ) -> Result<Interface<Self::Reader, Self::Writer>, DataLinkError>
    where
        Self: Sized;
}

/// Read-only packet interface
pub trait PacketInterfaceRead {
    /// Packet reader
    type Reader: PacketRead;

    /// Initialization of an interface
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init(name: &str) -> Result<InterfaceReader<Self::Reader>, DataLinkError>
    where
        Self: Sized;

    /// Initialization of an interface with a packet builder
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init_with_builder(
        name: &str,
        packet_builder: PacketBuilder,
    ) -> Result<InterfaceReader<Self::Reader>, DataLinkError>
    where
        Self: Sized;
}

/// Write-only packet interface
pub trait PacketInterfaceWrite {
    /// Packet writer
    type Writer: PacketWrite;

    /// Initialization of an interface
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init(name: &str) -> Result<InterfaceWriter<Self::Writer>, DataLinkError>
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
pub struct UnimplementedWriter;
impl PacketWrite for UnimplementedWriter {
    fn write(&mut self, _packet: Packet) -> Result<(), DataLinkError> {
        unimplemented!()
    }
}
/// Unimplemented packet reader
pub struct UnimplementedReader;
impl PacketRead for UnimplementedReader {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        unimplemented!()
    }
}

/// Reference to read-only interface
pub struct InterfaceReaderRef<'a, T>
where
    T: PacketRead,
{
    reader: &'a mut T,
}

/// Reference to write-only interface
pub struct InterfaceWriterRef<'a, T>
where
    T: PacketWrite,
{
    writer: &'a mut T,
}

/// Read-only interface
pub struct InterfaceReader<R>
where
    R: PacketRead,
{
    reader: R,
}

impl<R> InterfaceReader<R>
where
    R: PacketRead,
{
    /// Initialize read-only interface
    pub fn init<T: PacketInterfaceRead<Reader = R>>(
        name: &str,
    ) -> Result<InterfaceReader<T::Reader>, DataLinkError>
    where
        Self: Sized,
    {
        T::init(name)
    }

    /// Initialize read-only interface with custom builder
    pub fn init_with_builder<T: PacketInterfaceRead<Reader = R>>(
        name: &str,
        packet_builder: PacketBuilder,
    ) -> Result<InterfaceReader<T::Reader>, DataLinkError>
    where
        Self: Sized,
    {
        T::init_with_builder(name, packet_builder)
    }
}

/// Write-only interface
pub struct InterfaceWriter<W>
where
    W: PacketWrite,
{
    writer: W,
}

impl<W> InterfaceWriter<W>
where
    W: PacketWrite,
{
    /// Initialize write-only interface
    pub fn init<T: PacketInterfaceWrite<Writer = W>>(
        name: &str,
    ) -> Result<InterfaceWriter<T::Writer>, DataLinkError>
    where
        Self: Sized,
    {
        T::init(name)
    }
}

impl<'a, T: PacketRead> PacketRead for InterfaceReaderRef<'a, T> {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        self.reader.read()
    }
}

impl<T: PacketRead> PacketRead for InterfaceReader<T> {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        self.reader.read()
    }
}

impl<'a, T: PacketWrite> PacketWrite for InterfaceWriterRef<'a, T> {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        self.writer.write(packet)
    }
}

impl<T: PacketWrite> PacketWrite for InterfaceWriter<T> {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        self.writer.write(packet)
    }
}

impl<R: PacketRead, W: PacketWrite> Iterator for Interface<R, W> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        let packet = self.reader.read();
        if let Ok(packet) = packet {
            Some(packet)
        } else {
            None
        }
    }
}

impl<T: PacketRead> Iterator for InterfaceReaderRef<'_, T> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        let packet = self.reader.read();
        if let Ok(packet) = packet {
            Some(packet)
        } else {
            None
        }
    }
}

impl<T: PacketRead> Iterator for InterfaceReader<T> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        let packet = self.reader.read();
        if let Ok(packet) = packet {
            Some(packet)
        } else {
            None
        }
    }
}
