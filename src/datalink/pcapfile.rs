/*!
Packet interface implementation using `libpcap` to read pcap files

Note: Pcap writing currently not supported

libpcap interface exposed via libpnet
*/
use std::fs::File;

use pcap_file::{pcap::PcapReader, PcapError};

use super::{DataLinkError, PacketInterface, PacketRead};
use crate::{
    datalink::{Interface, InterfaceReader, PacketInterfaceRead, UnimplementedWriter},
    layer::ether::Ether,
    packet::{Packet, PacketParser},
};

/// Pcap file based interface
pub struct PcapFile {
    reader: PcapFileReader,
}

/// Pcap file reader
pub struct PcapFileReader {
    packet_parser: PacketParser,
    reader: PcapReader<File>,
}

impl PacketInterface for PcapFile {
    type Reader = PcapFileReader;
    type Writer = UnimplementedWriter; // TODO: support pcap file writing

    fn init(filename: &str) -> Result<Interface<Self::Reader, Self::Writer>, DataLinkError> {
        <Self as PacketInterface>::init_with_parser(filename, PacketParser::new())
    }

    fn init_with_parser(
        filename: &str,
        packet_parser: PacketParser,
    ) -> Result<Interface<Self::Reader, Self::Writer>, DataLinkError>
    where
        Self: Sized,
    {
        let file_in = File::open(filename)?;
        let reader = PcapReader::new(file_in)?;

        Ok(Interface {
            reader: PcapFileReader {
                packet_parser,
                reader,
            },
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
            <PcapFile as PacketInterface>::init_with_parser(name, packet_parser)?.into_split();

        Ok(reader)
    }
}

impl PacketRead for PcapFile {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        self.reader.read()
    }
}

impl PacketRead for PcapFileReader {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        match self.reader.next() {
            Some(Ok(packet)) => {
                let (_rest, packet) = self.packet_parser.parse_packet::<Ether>(&packet.data)?;
                // TODO: log warning of un-read data?
                Ok(packet)
            }
            Some(Err(e)) => match e {
                PcapError::IoError(e) => Err(DataLinkError::IoError(e)),
                _ => Err(DataLinkError::PcapError(e.to_string())),
            },
            None => Err(DataLinkError::Eof),
        }
    }
}
