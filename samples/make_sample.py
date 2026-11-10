"""Generate a harmless synthetic PCAP of TCP SYN packets for local testing."""
from pathlib import Path
import ipaddress, struct

def ipv4(s):return ipaddress.IPv4Address(s).packed

def packet(src,dst,port):
    eth=bytes.fromhex('00112233445566778899aabb0800')
    tcp=struct.pack('!HHIIHHHH',44000,port,1,0,0x5002,8192,0,0)
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40,0,0,64,6,0,ipv4(src),ipv4(dst))
    return eth+ip+tcp

def generate(path):
    out=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    for i in range(25):
        buf=packet('192.0.2.10','198.51.100.20',20+i)
        out+=struct.pack('<IIII',1760000000+i,0,len(buf),len(buf))+buf
    Path(path).write_bytes(out)

if __name__=='__main__':generate(Path(__file__).with_name('demo_scan.pcap'))
