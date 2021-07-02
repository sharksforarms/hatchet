/*!
Packet interface implementation using `libpnet`
*/
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};

use super::{DataLinkError, PacketInterface, PacketRead, PacketWrite};
use crate::{
    layer::ether::Ether,
    packet::{Packet, PacketBuilder},
};
use alloc::boxed::Box;

/// Pnet network interface
pub struct Pnet {
    packet_builder: PacketBuilder,
    rx: Box<dyn DataLinkReceiver + 'static>,
    tx: Box<dyn DataLinkSender + 'static>,
}

impl PacketInterface for Pnet {
    fn init_with_builder(
        interface_name: &str,
        packet_builder: PacketBuilder,
    ) -> Result<Self, DataLinkError> {
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

        Ok(Pnet {
            packet_builder,
            rx,
            tx,
        })
    }

    fn init(interface_name: &str) -> Result<Self, DataLinkError> {
        Self::init_with_builder(interface_name, PacketBuilder::new())
    }
}

impl PacketRead for Pnet {
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

impl PacketWrite for Pnet {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        let bytes = packet.to_bytes()?;
        if let Some(res) = self.tx.send_to(bytes.as_ref(), None) {
            Ok(res?)
        } else {
            Err(DataLinkError::BufferError)
        }
    }
}
