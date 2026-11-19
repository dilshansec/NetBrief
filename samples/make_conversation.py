"""Deterministic synthetic TCP teaching capture with valid IPv4/TCP checksums."""
from pathlib import Path
import struct
import ipaddress

def checksum(data):
    if len(data)%2: data += b'\0'
    total=sum(struct.unpack('!%dH' % (len(data)//2),data))
    while total>>16: total=(total&65535)+(total>>16)
    return (~total)&65535

def packet(src,dst,sport,dport,seq,ack,flags,payload=b''):
    a,b=ipaddress.ip_address(src).packed,ipaddress.ip_address(dst).packed
    tcp=struct.pack('!HHIIBBHHH',sport,dport,seq,ack,80,flags,65535,0,0)+payload
    pseudo=a+b+struct.pack('!BBH',0,6,len(tcp))
    tcp=tcp[:16]+struct.pack('!H',checksum(pseudo+tcp))+tcp[18:]
    ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(tcp),0,0,64,6,0,a,b)
    ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    return bytes.fromhex('00112233445566778899aabb0800')+ip+tcp

def records():
    a,b='192.0.2.10','198.51.100.20'
    def c(seq,ack,flags,data=b''): return packet(a,b,51524,80,seq,ack,flags,data)
    def s(seq,ack,flags,data=b''): return packet(b,a,80,51524,seq,ack,flags,data)
    request=b'GET /demo HTTP/1.1\r\nHost: example.test\r\n\r\n'
    response=b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello'
    x,y=1001+len(request),5001+len(response)
    return [c(1000,0,2),s(5000,1001,18),c(1001,5001,16),
            c(1001,5001,24,request),s(5001,x,16),s(5001,x,24,response),
            s(5001,x,24,response),c(x,y,16),c(x,y,17),s(y,x+1,16),
            s(y,x+1,17),c(x+1,y+1,16),
            packet(a,b,51525,443,2000,0,2),packet(a,b,51525,443,2000,0,2),
            packet(a,b,51526,22,3000,0,2),packet(b,a,22,51526,0,3001,20)]

def capture(packets=None):
    out=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    for i,buf in enumerate(records() if packets is None else packets):
        out+=struct.pack('<IIII',1760000000,i*20000,len(buf),len(buf))+buf
    return bytes(out)

if __name__=='__main__':
    Path(__file__).with_name('demo_conversation.pcap').write_bytes(capture())
