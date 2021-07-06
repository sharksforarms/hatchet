/*!
Packet interface implementation using `libpcap`

libpcap interface exposed via libpnet
*/
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};

use super::{DataLinkError, PacketInterface, PacketInterfaceSplit, PacketRead, PacketWrite};
use crate::{
    datalink::{Interface, InterfaceRx, InterfaceTx, PacketInterfaceRead, PacketInterfaceWrite},
    layer::ether::Ether,
    packet::{Packet, PacketBuilder},
};

/// LibPcap network interface
pub struct Pcap {
    rx: PcapRx,
    tx: PcapTx,
}

/// LibPcap reader
pub struct PcapRx {
    packet_builder: PacketBuilder,
    rx: Box<dyn DataLinkReceiver + 'static>,
}

/// LibPcap writer
pub struct PcapTx {
    tx: Box<dyn DataLinkSender + 'static>,
}

impl PacketInterface for Pcap {
    type Rx = PcapRx;
    type Tx = PcapTx;

    fn init(interface_name: &str) -> Result<Interface<Self::Rx, Self::Tx>, DataLinkError> {
        <Self as PacketInterface>::init_with_builder(interface_name, PacketBuilder::new())
    }

    fn init_with_builder(
        interface_name: &str,
        packet_builder: crate::packet::PacketBuilder,
    ) -> Result<Interface<Self::Rx, Self::Tx>, DataLinkError>
    where
        Self: Sized,
    {
        let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

        // Find the network interface with the provided name
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .filter(interface_names_match)
            .next()
            .ok_or(DataLinkError::InterfaceNotFound)?;

        let (tx, rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
            Ok(_) => Err(DataLinkError::UnhandledInterfaceType),
            Err(e) => Err(DataLinkError::IoError(e)),
        }?;

        Ok(Interface {
            rx: PcapRx { packet_builder, rx },
            tx: PcapTx { tx },
        })
    }
}

impl PacketInterfaceRead for Pcap {
    type Rx = PcapRx;

    fn init(name: &str) -> Result<InterfaceRx<Self::Rx>, DataLinkError>
    where
        Self: Sized,
    {
        <Self as PacketInterfaceRead>::init_with_builder(name, PacketBuilder::new())
    }

    fn init_with_builder(
        name: &str,
        packet_builder: PacketBuilder,
    ) -> Result<InterfaceRx<Self::Rx>, DataLinkError>
    where
        Self: Sized,
    {
        let (rx, _tx) =
            <Pcap as PacketInterface>::init_with_builder(name, packet_builder)?.into_split();

        Ok(rx)
    }
}

impl PacketInterfaceWrite for Pcap {
    type Tx = PcapTx;

    fn init(name: &str) -> Result<InterfaceTx<Self::Tx>, DataLinkError>
    where
        Self: Sized,
    {
        let (_rx, tx) = <Self as PacketInterface>::init(name)?.into_split();
        Ok(tx)
    }
}

impl PacketRead for Pcap {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        self.rx.read()
    }
}

impl PacketRead for PcapRx {
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

impl PacketWrite for Pcap {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        self.tx.write(packet)
    }
}

impl PacketWrite for PcapTx {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        let bytes = packet.to_bytes()?;
        if let Some(res) = self.tx.send_to(bytes.as_ref(), None) {
            Ok(res?)
        } else {
            Err(DataLinkError::BufferError)
        }
    }
}
