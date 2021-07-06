/*!
Packet interface implementation using `libpcap` to read pcap files

Note: Pcap writing currently not supported

libpcap interface exposed via libpnet
*/
use pnet::datalink::{self, Channel, DataLinkReceiver};

use super::{DataLinkError, PacketInterface, PacketRead};
use crate::{
    datalink::{Interface, InterfaceReader, PacketInterfaceRead, UnimplementedWriter},
    layer::ether::Ether,
    packet::{Packet, PacketBuilder},
};

/// Pcap file based interface
pub struct PcapFile {
    rx: PcapFileReader,
}

/// Pcap file reader
pub struct PcapFileReader {
    packet_builder: PacketBuilder,
    rx: Box<dyn DataLinkReceiver + 'static>,
}

impl PacketInterface for PcapFile {
    type Reader = PcapFileReader;
    type Writer = UnimplementedWriter; // TODO: support pcap file writing

    fn init(filename: &str) -> Result<Interface<Self::Reader, Self::Writer>, DataLinkError> {
        <Self as PacketInterface>::init_with_builder(filename, PacketBuilder::new())
    }

    fn init_with_builder(
        filename: &str,
        packet_builder: PacketBuilder,
    ) -> Result<Interface<Self::Reader, Self::Writer>, DataLinkError>
    where
        Self: Sized,
    {
        let (_tx, rx) = match datalink::pcap::from_file(filename, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
            Ok(_) => Err(DataLinkError::UnhandledInterfaceType),
            Err(e) => Err(DataLinkError::IoError(e)),
        }?;

        Ok(Interface {
            reader: PcapFileReader { packet_builder, rx },
            writer: UnimplementedWriter {},
        })
    }
}

impl PacketInterfaceRead for PcapFile {
    type Reader = PcapFileReader;

    fn init(name: &str) -> Result<InterfaceReader<Self::Reader>, DataLinkError>
    where
        Self: Sized,
    {
        <Self as PacketInterfaceRead>::init_with_builder(name, PacketBuilder::new())
    }

    fn init_with_builder(
        name: &str,
        packet_builder: PacketBuilder,
    ) -> Result<InterfaceReader<Self::Reader>, DataLinkError>
    where
        Self: Sized,
    {
        let (reader, _writer) =
            <PcapFile as PacketInterface>::init_with_builder(name, packet_builder)?.into_split();

        Ok(reader)
    }
}

impl PacketRead for PcapFile {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        self.rx.read()
    }
}

impl PacketRead for PcapFileReader {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        match self.rx.next() {
            Ok(packet_bytes) => {
                let (_rest, packet) = self.packet_builder.parse_packet::<Ether>(packet_bytes)?;
                // TODO: log warning of un-read data?
                Ok(packet)
            }
            Err(e) => Err(DataLinkError::IoError(e)),
        }
    }
}
