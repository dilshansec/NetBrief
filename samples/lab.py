"""Offline synthetic packets only: no sockets, traffic transmission or attacks."""
import ipaddress
import struct
import random
from samples.make_conversation import packet, records, checksum
MIXED_CATEGORIES=('port_scan','arp_spoofing','dns_tunneling','icmp_flood')
NAMES={'mixed':'Four suspicious activities (demo)','normal':'Normal TCP conversation','port_scan':'Port scan indicators','host_discovery':'Host discovery','syn_flood':'SYN flood indicators','brute_force':'Repeated SSH connections','arp_spoofing':'Conflicting ARP claims','dns_tunneling':'DNS tunneling indicators','icmp_flood':'ICMP flood indicators','exfiltration':'Large outbound transfer','beaconing':'Periodic connections'}


def datagram(src,dst,protocol,payload):
    a,b=ipaddress.ip_address(src).packed,ipaddress.ip_address(dst).packed
    ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(payload),0,0,64,protocol,0,a,b)
    ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    return bytes.fromhex('00112233445566778899aabb0800')+ip+payload


def scenario_rows(name):
    a,b='10.0.0.10','198.51.100.20'; rows=[]
    if name=='mixed':
        for index,category in enumerate(MIXED_CATEGORIES):
            for elapsed,raw in scenario_rows(category):
                # A separate ARP recipient gives five hosts across three IP pairs.
                if category=='arp_spoofing':
                    raw=raw[:-4]+ipaddress.ip_address('10.0.0.11').packed
                rows.append((index*300+elapsed,raw))
        # Ordinary ACK traffic on the existing TCP pair: 309 + 12 = 321 frames.
        rows.extend((1200+i*.02,packet(a,b,40000,20,2000+i,1,16)) for i in range(12))
    elif name=='normal':rows=[(i*.02,p) for i,p in enumerate(records())]
    elif name in ('port_scan','syn_flood','brute_force','beaconing'):
        count={'port_scan':30,'syn_flood':250,'brute_force':25,'beaconing':10}[name]
        rows=[(i*(30 if name=='beaconing' else .02),packet(a,b,40000+i,20+i if name=='port_scan' else 22 if name=='brute_force' else 443,1000+i,0,2)) for i in range(count)]
    elif name in ('host_discovery','icmp_flood'):
        for i in range(30 if name=='host_discovery' else 250):
            body=struct.pack('!BBHHH',8,0,0,1,i)+b'lab'
            body=body[:2]+struct.pack('!H',checksum(body))+body[4:]
            rows.append((i*.02,datagram(a,f'10.0.1.{i+1}' if name=='host_discovery' else b,1,body)))
    elif name=='arp_spoofing':
        for i in range(4):
            mac=bytes.fromhex('66778899aabb' if i%2 else '66778899aacc')
            arp=struct.pack('!HHBBH',1,0x800,6,4,2)+mac+ipaddress.ip_address('10.0.0.1').packed+bytes(6)+ipaddress.ip_address(a).packed
            rows.append((i,bytes.fromhex('ffffffffffff')+mac+bytes.fromhex('0806')+arp))
    elif name=='dns_tunneling':
        rng=random.Random(42)
        for i in range(25):
            label=''.join(rng.choices('abcdefghijklmnopqrstuvwxyz0123456789',k=48))
            q=b''.join(bytes([len(s)])+s.encode() for s in (label,'example','test'))+b'\0'+struct.pack('!HH',16,1)
            dns=struct.pack('!6H',i,256,1,0,0,0)+q
            udp=struct.pack('!HHHH',45000+i,53,len(dns)+8,0)+dns
            rows.append((i*.1,datagram(a,'10.0.0.53',17,udp)))
    elif name=='exfiltration':
        rows=[(i*.01,packet(a,b,45000,443,1000+i*1400,1,24,b'x'*1400)) for i in range(3500)]
    else:raise ValueError('Unknown sample')
    return rows


def generate(name):
    rows=scenario_rows(name)
    out=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    for elapsed,raw in rows:
        secs=int(elapsed);micro=round((elapsed-secs)*1000000)
        out+=struct.pack('<IIII',1760000040+secs,micro,len(raw),len(raw))+raw
    return bytes(out)
