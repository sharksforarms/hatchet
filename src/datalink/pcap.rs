/*!
Packet interface implementation using `libpcap`

libpcap interface exposed via libpnet
*/
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};

use super::{DataLinkError, PacketInterface, PacketRead, PacketWrite};
use crate::{
    datalink::{
        Interface, InterfaceReader, InterfaceWriter, PacketInterfaceRead, PacketInterfaceWrite,
    },
    layer::ether::Ether,
    packet::{Packet, PacketParser},
};

/// LibPcap network interface
pub struct Pcap {
    reader: PcapReader,
    writer: PcapWriter,
}

/// LibPcap reader
pub struct PcapReader {
    packet_parser: PacketParser,
    reader: Box<dyn DataLinkReceiver + 'static>,
}

/// LibPcap writer
pub struct PcapWriter {
    writer: Box<dyn DataLinkSender + 'static>,
}

impl PacketInterface for Pcap {
    type Reader = PcapReader;
    type Writer = PcapWriter;

    fn init(interface_name: &str) -> Result<Interface<Self::Reader, Self::Writer>, DataLinkError> {
        <Self as PacketInterface>::init_with_parser(interface_name, PacketParser::new())
    }

    fn init_with_parser(
        interface_name: &str,
        packet_parser: crate::packet::PacketParser,
    ) -> Result<Interface<Self::Reader, Self::Writer>, DataLinkError>
    where
        Self: Sized,
    {
        let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

        // Find the network interface with the provided name
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(interface_names_match)
            .ok_or(DataLinkError::InterfaceNotFound)?;

        let (tx, rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
            Ok(_) => Err(DataLinkError::UnhandledInterfaceType),
            Err(e) => Err(DataLinkError::IoError(e)),
        }?;

        Ok(Interface {
            reader: PcapReader {
                packet_parser,
                reader: rx,
            },
            writer: PcapWriter { writer: tx },
        })
    }
}

impl PacketInterfaceRead for Pcap {
    type Reader = PcapReader;

    fn init(name: &str) -> Result<InterfaceReader<Self::Reader>, DataLinkError>
    where
        Self: Sized,
    {
        <Self as PacketInterfaceRead>::init_with_parser(name, PacketParser::new())
    }

    fn init_with_parser(
        name: &str,
        packet_parser: PacketParser,
    ) -> Result<InterfaceReader<Self::Reader>, DataLinkError>
    where
        Self: Sized,
    {
        let (reader, _writer) =
            <Pcap as PacketInterface>::init_with_parser(name, packet_parser)?.into_split();

        Ok(reader)
    }
}

impl PacketInterfaceWrite for Pcap {
    type Writer = PcapWriter;

    fn init(name: &str) -> Result<InterfaceWriter<Self::Writer>, DataLinkError>
    where
        Self: Sized,
    {
        let (_reader, writer) = <Self as PacketInterface>::init(name)?.into_split();
        Ok(writer)
    }
}

impl PacketRead for Pcap {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        self.reader.read()
    }
}

impl PacketRead for PcapReader {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        match self.reader.next() {
            Ok(packet_bytes) => {
                let (_rest, packet) = self.packet_parser.parse_packet::<Ether>(packet_bytes)?;
                // TODO: log warning of un-read data?
                Ok(packet)
            }
            Err(e) => Err(DataLinkError::IoError(e)),
        }
    }
}

impl PacketWrite for Pcap {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        self.writer.write(packet)
    }
}

impl PacketWrite for PcapWriter {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        let bytes = packet.to_bytes()?;
        if let Some(res) = self.writer.send_to(bytes.as_ref(), None) {
            Ok(res?)
        } else {
            Err(DataLinkError::BufferError)
        }
    }
}
