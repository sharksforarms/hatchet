/*!
Packet interface implementation using `libpcap` to read pcap files

Note: Pcap writing currently not supported

libpcap interface exposed via libpnet
*/
use pnet::datalink::{self, Channel, DataLinkReceiver};

use super::{DataLinkError, PacketInterface, PacketRead, PacketWrite};
use crate::{
    layer::ether::Ether,
    packet::{Packet, PacketBuilder},
};

pub struct PcapFile {
    packet_builder: PacketBuilder,
    rx: Box<dyn DataLinkReceiver + 'static>,
    // tx: Box<dyn DataLinkSender + 'static>, // TODO: implement pcap writing
}

impl PacketInterface for PcapFile {
    fn init(filename: &str) -> Result<Self, DataLinkError> {
        Self::init_with_builder(filename, PacketBuilder::new())
    }

    fn init_with_builder(
        filename: &str,
        packet_builder: PacketBuilder,
    ) -> Result<Self, DataLinkError>
    where
        Self: Sized,
    {
        let (_tx, rx) = match datalink::pcap::from_file(filename, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
            Ok(_) => Err(DataLinkError::UnhandledInterfaceType),
            Err(e) => Err(DataLinkError::IoError(e)),
        }?;

        Ok(PcapFile { packet_builder, rx })
    }
}

impl PacketRead for PcapFile {
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

impl PacketWrite for PcapFile {
    fn write(&mut self, _packet: Packet) -> Result<(), DataLinkError> {
        unimplemented!();
    }
}
