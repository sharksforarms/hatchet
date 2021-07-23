from scapy.all import *
from pathlib import Path
import os
from scapy.layers.usb import USBpcap

PWD = Path(__file__).parent.resolve()


def generate_pcap(packets, name: str):
    out_name = os.path.join(PWD, name)
    wrpcap(out_name, packets)


# Test read/write combinations
generate_pcap([
    Ether(),
    Ether()/b"data",
    Ether(type=0x0800)/IP(),
    Ether(type=0x0800)/IP()/b"data",
    Ether(type=0x86dd)/IPv6(),
    Ether(type=0x86dd)/IPv6()/b"data",
    Ether(type=0x0800)/IP()/UDP(),
    Ether(type=0x0800)/IP()/UDP()/b"data",
    Ether(type=0x0800)/IP()/TCP(),
    Ether(type=0x0800)/IP()/TCP()/b"data",
    Ether(type=0x86dd)/IPv6(nh=17)/UDP(),
    Ether(type=0x86dd)/IPv6(nh=17)/UDP()/b"data",
    Ether(type=0x86dd)/IPv6(nh=6)/TCP(),
    Ether(type=0x86dd)/IPv6(nh=6)/TCP()/b"data",
], 'test_pcap_read_write.pcap')


generate_pcap([
    USBpcap()
], 'test_pcap_unhandled_read_write.pcap')
