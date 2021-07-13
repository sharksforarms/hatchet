/*!
Packet interface implementation using `libpcap` to read pcap files

Note: Pcap writing currently not supported

libpcap interface exposed via libpnet
*/
use crate::{
    datalink::{
        error::DataLinkError, InterfaceReader, InterfaceWriter, PacketInterfaceRead,
        PacketInterfaceWrite, PacketRead, PacketWrite,
    },
    layer::ether::Ether,
    packet::{Packet, PacketParser},
};
use core::convert::TryFrom;
use pcap_file::{pcap::PcapReader, PcapWriter};
use std::fs::File;

/// Pcap file based interface
pub struct PcapFile {}

/// Pcap file reader
pub struct PcapFileReader {
    packet_parser: PacketParser,
    reader: PcapReader<File>,
}

/// Pcap file writer
pub struct PcapFileWriter {
    writer: PcapWriter<File>,
}

impl PacketInterfaceRead for PcapFile {
    type Reader = PcapFileReader;

    fn init(filename: &str) -> Result<InterfaceReader<Self::Reader>, DataLinkError>
    where
        Self: Sized,
    {
        <Self as PacketInterfaceRead>::init_with_parser(filename, PacketParser::new())
    }

    fn init_with_parser(
        filename: &str,
        packet_parser: PacketParser,
    ) -> Result<InterfaceReader<Self::Reader>, DataLinkError>
    where
        Self: Sized,
    {
        let file_in = File::open(filename)?;
        let reader = PcapReader::new(file_in)?;

        Ok(InterfaceReader {
            reader: PcapFileReader {
                packet_parser,
                reader,
            },
        })
    }
}

impl PacketInterfaceWrite for PcapFile {
    type Writer = PcapFileWriter;

    fn init(filename: &str) -> Result<super::InterfaceWriter<Self::Writer>, DataLinkError>
    where
        Self: Sized,
    {
        let file_in = File::create(filename)?;
        let writer = PcapWriter::new(file_in)?;

        Ok(InterfaceWriter {
            writer: PcapFileWriter { writer },
        })
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
            Some(Err(e)) => Err(e.into()),
            None => Err(DataLinkError::Eof),
        }
    }
}

impl PacketWrite for PcapFileWriter {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        let data = packet.to_bytes()?;
        let data_len = u32::try_from(data.len()).map_err(|_e| {
            DataLinkError::PcapError(format!(
                "failed to convert packet length {} > {}",
                data.len(),
                u32::MAX
            ))
        })?;

        let ts = chrono::offset::Utc::now();
        let ts_sec = u32::try_from(ts.timestamp()).map_err(|_e| {
            DataLinkError::PcapError(format!(
                "failed to convert timestamp {} > {}",
                ts.timestamp(),
                u32::MAX
            ))
        })?;
        let ts_nsec = ts.timestamp_subsec_nanos();

        match self.writer.write(ts_sec, ts_nsec, &data, data_len) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
