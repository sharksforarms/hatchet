/*!
  Rust packet is a network packet manipulation toolkit.

  This library enables parsing and crafting of network packets and
  can be extended to your own protocols.

  This library takes inspiration from Python's [Scapy](https://scapy.net/).
*/
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

pub mod layer;
pub mod packet;

pub mod datalink;
