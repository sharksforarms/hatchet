/*!
Hachet is a network packet manipulation toolkit.

This library takes inspiration from Python's [Scapy](https://scapy.net/).

Hachet enables extensible parsing and crafting of network packets.

# Packet

Data sent over a network such as the Internet, are split up into packets.

A [Packet](crate::packet::Packet) is defined as a collection of
[Layer](crate::layer::Layer).

A Layer represents the layout structure of a specific protocol (such as [Tcp](crate::layer::tcp::Tcp)).

# Layer

Hachet has [layer implementations](./layer/trait.LayerExt.html#implementors) for many core protocols.

For custom protocols or those implemented in hachet already, see [layer](crate::layer) for examples on adding a new layer.

Contributions are welcome to add new protocols! See [here](https://github.com/sharksforarms/hatchet) for more information.

# Packet Parser

The packet parser defines the heuristics on which layer to parse next, given the current layer and
the remaining bytes.

Hachet provides default layer bindings for layers it implements. These can be found [here](crate::packet::bindings).

# Interface

An [Interface](crate::datalink::Interface) provides the circuitry necessary to perform I/O with packets.

This could be reading/writing from/to a network interface, a pcap file, or other.

See [here](crate::datalink) for more information.
*/
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

pub mod layer;
pub mod packet;

#[cfg(feature = "std")]
pub mod datalink;
