use hachet::datalink::{pcapfile::PcapFile, InterfaceReader};

#[test]
#[cfg_attr(miri, ignore)]
fn test_pcap_read_write() {
    let interface =
        InterfaceReader::init::<PcapFile>("./tests/pcaps/test_pcap_read_write.pcap").unwrap();

    let mut count = 0;
    for mut pkt in interface {
        let bytes1 = pkt.to_bytes().unwrap();
        pkt.finalize().unwrap();
        let bytes2 = pkt.to_bytes().unwrap();

        assert_eq!(bytes1, bytes2);
        count += 1;
    }

    assert_eq!(14, count);
}
