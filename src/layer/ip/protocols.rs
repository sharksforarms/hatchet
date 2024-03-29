/*!
  IP protocols
*/
use alloc::{format, vec::Vec};
use deku::prelude::*;

/// Ip Protocols
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Clone, Copy, DekuRead, DekuWrite)]
#[deku(
    type = "u8",
    ctx = "endian: deku::ctx::Endian",
    ctx_default = "deku::ctx::Endian::Big",
    endian = "endian"
)]
#[non_exhaustive]
pub enum IpProtocol {
    /// IPv6 Hop-by-Hop Option [RFC1883](https://datatracker.ietf.org/doc/html/rfc1883)
    #[deku(id = "0")]
    HOPOPT,
    /// internet control message protocol
    #[deku(id = "1")]
    ICMP,
    /// Internet Group Management
    #[deku(id = "2")]
    IGMP,
    /// gateway-gateway protocol
    #[deku(id = "3")]
    GGP,
    /// IP encapsulated in IP (officially ``IP'')
    #[deku(id = "4")]
    IPENCAP,
    /// ST datagram mode
    #[deku(id = "5")]
    ST,
    /// transmission control protocol
    #[deku(id = "6")]
    TCP,
    /// exterior gateway protocol
    #[deku(id = "8")]
    EGP,
    /// any private interior gateway (Cisco)
    #[deku(id = "9")]
    IGP,
    /// PARC universal packet protocol
    #[deku(id = "12")]
    PUP,
    /// user datagram protocol
    #[deku(id = "17")]
    UDP,
    /// host monitoring protocol
    #[deku(id = "20")]
    HMP,
    /// Xerox NS IDP
    #[deku(id = "22")]
    XNSIDP,
    /// "reliable datagram" protocol
    #[deku(id = "27")]
    RDP,
    /// ISO Transport Protocol class 4 [RFC905](https://datatracker.ietf.org/doc/html/rfc905)
    #[deku(id = "29")]
    ISOTP4,
    /// Datagram Congestion Control Prot. [RFC4340](https://datatracker.ietf.org/doc/html/rfc4340)
    #[deku(id = "33")]
    DCCP,
    /// Xpress Transfer Protocol
    #[deku(id = "36")]
    XTP,
    /// Datagram Delivery Protocol
    #[deku(id = "37")]
    DDP,
    /// IDPR Control Message Transport
    #[deku(id = "38")]
    IDPRCMTP,
    /// Internet Protocol, version 6
    #[deku(id = "41")]
    IPV6,
    /// Routing Header for IPv6
    #[deku(id = "43")]
    IPV6ROUTE,
    /// Fragment Header for IPv6
    #[deku(id = "44")]
    IPV6FRAG,
    /// Inter-Domain Routing Protocol
    #[deku(id = "45")]
    IDRP,
    /// Reservation Protocol
    #[deku(id = "46")]
    RSVP,
    /// General Routing Encapsulation
    #[deku(id = "47")]
    GRE,
    /// Encap Security Payload [RFC2406](https://datatracker.ietf.org/doc/html/rfc2406)
    #[deku(id = "50")]
    ESP,
    /// Authentication Header [RFC2402](https://datatracker.ietf.org/doc/html/rfc2402)
    #[deku(id = "51")]
    AH,
    /// SKIP
    #[deku(id = "57")]
    SKIP,
    /// ICMP for IPv6
    #[deku(id = "58")]
    IPV6ICMP,
    /// No Next Header for IPv6
    #[deku(id = "59")]
    IPV6NONXT,
    /// Destination Options for IPv6
    #[deku(id = "60")]
    IPV6OPTS,
    /// Radio Shortest Path First (officially CPHB)
    #[deku(id = "73")]
    RSPF,
    /// Versatile Message Transport
    #[deku(id = "81")]
    VMTP,
    /// Enhanced Interior Routing Protocol (Cisco)
    #[deku(id = "88")]
    EIGRP,
    /// Open Shortest Path First IGP
    #[deku(id = "89")]
    OSPF,
    /// AX.25 frames
    #[deku(id = "93")]
    AX25,
    /// IP-within-IP Encapsulation Protocol
    #[deku(id = "94")]
    IPIP,
    /// Ethernet-within-IP Encapsulation [RFC3378](https://datatracker.ietf.org/doc/html/rfc3378)
    #[deku(id = "97")]
    ETHERIP,
    /// Yet Another IP encapsulation [RFC1241](https://datatracker.ietf.org/doc/html/rfc1241)
    #[deku(id = "98")]
    ENCAP,
    /// Protocol Independent Multicast
    #[deku(id = "103")]
    PIM,
    /// IP Payload Compression Protocol
    #[deku(id = "108")]
    IPCOMP,
    /// Virtual Router Redundancy Protocol [RFC5798](https://datatracker.ietf.org/doc/html/rfc5798)
    #[deku(id = "112")]
    VRRP,
    /// Layer Two Tunneling Protocol [RFC2661](https://datatracker.ietf.org/doc/html/rfc2661)
    #[deku(id = "115")]
    L2TP,
    /// IS-IS over IPv4
    #[deku(id = "124")]
    ISIS,
    /// Stream Control Transmission Protocol
    #[deku(id = "132")]
    SCTP,
    /// Fibre Channel
    #[deku(id = "133")]
    FC,
    /// Mobility Support for IPv6 [RFC3775](https://datatracker.ietf.org/doc/html/rfc3775)
    #[deku(id = "135")]
    MOBILITYHEADER,
    /// UDP-Lite [RFC3828](https://datatracker.ietf.org/doc/html/rfc3828)
    #[deku(id = "136")]
    UDPLITE,
    /// MPLS-in-IP [RFC4023](https://datatracker.ietf.org/doc/html/rfc4023)
    #[deku(id = "137")]
    MPLSINIP,
    /// MANET Protocols [RFC5498](https://datatracker.ietf.org/doc/html/rfc5498)
    #[deku(id = "138")]
    MANET,
    /// Host Identity Protocol
    #[deku(id = "139")]
    HIP,
    /// Shim6 Protocol [RFC5533](https://datatracker.ietf.org/doc/html/rfc5533)
    #[deku(id = "140")]
    SHIM6,
    /// Wrapped Encapsulating Security Payload
    #[deku(id = "141")]
    WESP,
    /// Robust Header Compression
    #[deku(id = "142")]
    ROHC,
    /// Unknown ip protocol
    #[deku(id_pat = "_")]
    Unknown(u8),
}

impl Default for IpProtocol {
    fn default() -> Self {
        IpProtocol::TCP
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipprotocol_rw() {
        let test_data = [0x06u8].to_vec();

        let (_rest, ret_read) = IpProtocol::from_bytes((&test_data, 0)).unwrap();
        assert_eq!(IpProtocol::TCP, ret_read);

        let ret_write = ret_read.to_bytes().unwrap();
        assert_eq!(test_data, ret_write);
    }

    #[test]
    fn test_ipprotocol_default() {
        assert_eq!(IpProtocol::TCP, IpProtocol::default())
    }
}
