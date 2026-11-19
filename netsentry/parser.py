"""Dependency-free PCAP/PCAPNG metadata reader (no payload storage)."""
from netsentry.connections import Conversations
from netsentry.metadata import dns_message, application
import os
import ipaddress
import struct
from collections import Counter
from datetime import datetime, timezone

MAX_PACKETS = int(os.getenv("NETSENTRY_MAX_PACKETS", "50000"))

class CaptureError(ValueError):
    pass


def frames(blob):
    if len(blob) < 12:
        raise CaptureError('Capture too short')
    magic = blob[:4]
    formats = {b'\xd4\xc3\xb2\xa1': ('<',1_000_000), b'\xa1\xb2\xc3\xd4': ('>',1_000_000),
               b'\x4d\x3c\xb2\xa1': ('<',1_000_000_000), b'\xa1\xb2\x3c\x4d': ('>',1_000_000_000)}
    if magic in formats:
        endian, resolution = formats[magic]
        if len(blob) < 24: raise CaptureError('Truncated PCAP header')
        major,minor=struct.unpack_from(endian+'HH',blob,4)
        if (major,minor)!=(2,4):raise CaptureError('Unsupported PCAP version')
        network = struct.unpack_from(endian+'I',blob,20)[0] & 0xffff
        pos=24
        while pos < len(blob):
            if pos+16 > len(blob): raise CaptureError('Truncated PCAP packet header')
            sec,frac,incl,orig = struct.unpack_from(endian+'IIII',blob,pos)
            pos+=16
            if incl > len(blob)-pos: raise CaptureError('Truncated PCAP packet')
            yield sec+frac/resolution,network,blob[pos:pos+incl],orig
            pos+=incl
        return
    if magic != b'\x0a\x0d\x0d\x0a': raise CaptureError('Not a recognized PCAP or PCAPNG file')
    pos=0; endian=None; interfaces=[]
    while pos < len(blob):
        if pos+12 > len(blob): raise CaptureError('Truncated PCAPNG block')
        if blob[pos:pos+4] == magic:
            bom=blob[pos+8:pos+12]
            endian='<' if bom==b'\x4d\x3c\x2b\x1a' else '>' if bom==b'\x1a\x2b\x3c\x4d' else None
            if endian is None: raise CaptureError('Invalid PCAPNG byte-order marker')
            interfaces=[]
        elif endian is None: raise CaptureError('Missing PCAPNG section header')
        kind,size=struct.unpack_from(endian+'II',blob,pos)
        if size < 12 or size%4 or pos+size > len(blob): raise CaptureError('Invalid PCAPNG block size')
        if struct.unpack_from(endian+'I',blob,pos+size-4)[0] != size: raise CaptureError('PCAPNG block length mismatch')
        body=pos+8; end=pos+size-4
        if kind==0x0a0d0d0a and size<28:raise CaptureError('Truncated PCAPNG section header')
        if kind==1 and end-body<8:raise CaptureError('Truncated PCAPNG interface')
        if kind in (2,6) and end-body<20:raise CaptureError('Truncated PCAPNG packet header')
        if kind==1 and end-body>=8:
            link=struct.unpack_from(endian+'H',blob,body)[0]; scale=1e-6; offset=0
            opt=body+8
            while opt+4<=end:
                code,length=struct.unpack_from(endian+'HH',blob,opt); opt+=4
                if code==0: break
                if opt+length>end: break
                data=blob[opt:opt+length]
                if code==9 and length>=1:
                    val=data[0]; scale= (2**-(val&127)) if (val&128) else (10**-val)
                if code==14 and length==8: offset=struct.unpack(endian+'q',data)[0]
                opt+=(length+3)&~3
            interfaces.append((link,scale,offset))
        elif kind==6 and end-body>=20:
            iid,high,low,caplen,origlen=struct.unpack_from(endian+'IIIII',blob,body)
            if iid>=len(interfaces) or caplen > end-(body+20): raise CaptureError('Invalid PCAPNG enhanced packet')
            link,scale,offset=interfaces[iid]
            yield ((high<<32)|low)*scale+offset,link,blob[body+20:body+20+caplen],origlen
        elif kind==3 and end-body>=4 and interfaces:
            original=struct.unpack_from(endian+'I',blob,body)[0]
            yield None, interfaces[0][0], blob[body+4:end][:original],original
        elif kind==2 and end-body>=20 and interfaces:
            iid,_,high,low,caplen,origlen=struct.unpack_from(endian+'HHIIII',blob,body)
            if iid<len(interfaces) and caplen<=end-(body+20):
                link,scale,offset=interfaces[iid]
                yield ((high<<32)|low)*scale+offset,link,blob[body+20:body+20+caplen],origlen
        pos+=size


def decode(link, data):
    out={'src':'—','dst':'—','sport':None,'dport':None,'protocol':'OTHER','syn':False,'ack':False}
    offset=0; proto=None
    if link==1:
        if len(data)<14: return out
        out.update(src_mac=data[6:12].hex(':'), dst_mac=data[:6].hex(':'))
        etype=struct.unpack_from('!H',data,12)[0];offset=14
        for _ in range(2):
            if etype in (0x8100,0x88a8) and len(data)>=offset+4:
                etype=struct.unpack_from('!H',data,offset+2)[0];offset+=4
        if etype==0x0806:
            out['protocol']='ARP'
            if len(data)>=offset+28 and data[offset:offset+6]==b'\x00\x01\x08\x00\x06\x04':
                out.update(arp_op=int.from_bytes(data[offset+6:offset+8], 'big'), src=str(ipaddress.IPv4Address(data[offset+14:offset+18])), dst=str(ipaddress.IPv4Address(data[offset+24:offset+28])), arp_mac=data[offset+8:offset+14].hex(':'))
            return out
        if etype==0x0800: proto=4
        elif etype==0x86dd: proto=6
    elif link in (101,228,229):
        proto= (data[0]>>4) if data else None
    elif link==113 and len(data)>=16:
        etype=struct.unpack_from('!H',data,14)[0];offset=16
        proto=4 if etype==0x800 else 6 if etype==0x86dd else None
    if proto==4:
        if len(data)<offset+20: return out
        vihl=data[offset];ihl=(vihl&15)*4
        if vihl>>4!=4 or ihl<20 or len(data)<offset+ihl:return out
        out['src']=str(ipaddress.IPv4Address(data[offset+12:offset+16]));out['dst']=str(ipaddress.IPv4Address(data[offset+16:offset+20]))
        protocol=data[offset+9];fragment=struct.unpack_from('!H',data,offset+6)[0]&0x1fff
        ip_end=offset+struct.unpack_from('!H',data,offset+2)[0]
        if ip_end<offset+ihl:raise ValueError('Invalid IPv4 total length')
        fragmented=bool(struct.unpack_from('!H',data,offset+6)[0]&0x3fff)
        data=data[:ip_end]
        offset+=ihl
        if fragment: out['protocol']='IPv4 fragment';return out
    elif proto==6:
        if len(data)<offset+40 or data[offset]>>4!=6:return out
        out['src']=str(ipaddress.IPv6Address(data[offset+8:offset+24]));out['dst']=str(ipaddress.IPv6Address(data[offset+24:offset+40]))
        ip_end=offset+40+struct.unpack_from('!H',data,offset+4)[0]
        data=data[:ip_end]; fragmented=False
        protocol=data[offset+6];offset+=40
        for _ in range(8):
            if protocol in (0,43,60) and len(data)>=offset+2:
                nextproto=data[offset]; step=(data[offset+1]+1)*8
                if len(data)<offset+step:return out
                protocol=nextproto;offset+=step
            elif protocol==44 and len(data)>=offset+8:
                nextproto=data[offset];frag=struct.unpack_from('!H',data,offset+2)[0]
                fragmented=True
                protocol=nextproto;offset+=8
                if frag&0xfff8:out['protocol']='IPv6 fragment';return out
            else:break
    else:return out
    names={6:'TCP',17:'UDP',1:'ICMP',58:'ICMPv6'}
    out['protocol']=names.get(protocol,'IP other')
    if protocol in (6,17) and len(data)>=offset+4:
        out['sport'],out['dport']=struct.unpack_from('!HH',data,offset)
        if protocol==6 and len(data)>=offset+14:
            flags=data[offset+13]
            out['syn']=bool(flags&2);out['ack']=bool(flags&16)
    if protocol==6 and not fragmented and len(data)>=offset+20:
        header=(data[offset+12]>>4)*4
        if header>=20 and offset+header<=len(data):
            flags=data[offset+13]
            out.update(seq=struct.unpack_from('!I',data,offset+4)[0], ack_number=struct.unpack_from('!I',data,offset+8)[0],
                       flags=[name for mask,name in ((2,'SYN'),(16,'ACK'),(8,'PSH'),(1,'FIN'),(4,'RST'),(32,'URG'),(64,'ECE'),(128,'CWR')) if flags&mask],
                       payload_bytes=len(data)-offset-header, truncated=len(data)<ip_end)
    if protocol==6 and out.get('seq') is not None:
        out.update(application(data[offset+header:], out['sport'], out['dport']))
    if protocol in (1,58) and len(data)>offset:
        out['icmp_type']=data[offset]
    if protocol==17 and not fragmented and len(data)>=offset+8:
        size=struct.unpack_from('!H',data,offset+4)[0]
        if size>=8 and (out['sport']==53 or out['dport']==53):
            out['protocol']='DNS'
            out.update(dns_message(data[offset+8:offset+size]))
    return out


def analyze(blob, filename, config=None):
    protocols=Counter();sources=Counter();destinations=Counter();ports=Counter(); timeline=Counter(); volume=Counter()
    conversations=Conversations()
    packets=[]; count=0; first=None;last=None; parse_errors=0;total_bytes=0
    for timestamp,link,raw,orig in frames(blob):
        count+=1
        if count>MAX_PACKETS:raise CaptureError(f'Packet count exceeds limit ({MAX_PACKETS:,})')
        try: p=decode(link,raw)
        except (ValueError,struct.error):
            parse_errors+=1;p={'src':'—','dst':'—','sport':None,'dport':None,'protocol':'MALFORMED','syn':False,'ack':False}
        connection_id=conversations.add(p,count,timestamp)
        protocols[p['protocol']]+=1;total_bytes+=orig
        if p['src']!='—':sources[p['src']]+=1;destinations[p['dst']]+=1
        if p['dport'] is not None:ports[str(p['dport'])]+=1
        if timestamp is not None:
            first=timestamp if first is None else min(first,timestamp)
            last=timestamp if last is None else max(last,timestamp)
            bucket=datetime.fromtimestamp(max(0,min(timestamp,253402300799)),tz=timezone.utc).strftime('%Y-%m-%d %H:%M')
            timeline[bucket]+=1;volume[bucket]+=len(raw)
        packets.append({'no':count,'time':datetime.fromtimestamp(timestamp,tz=timezone.utc).isoformat() if timestamp is not None and 0<=timestamp<253402300799 else None,
                            'src':p['src'],'dst':p['dst'],'protocol':p['protocol'],'sport':p['sport'],'dport':p['dport'],'length':orig,'flags':p.get('flags',[]),'seq':p.get('seq'),'ack_number':p.get('ack_number'),'payload_bytes':p.get('payload_bytes'),'connection_id':connection_id, 'timestamp':timestamp, 'captured_length':len(raw), **{k:p[k] for k in ('src_mac','dst_mac','arp_op','arp_mac','dns_query','dns_response','dns_rcode','dns_type','dns_answers','http','tls','auth_failure','icmp_type') if k in p}})
    iso=lambda t:datetime.fromtimestamp(t,tz=timezone.utc).isoformat() if t is not None and 0<=t<253402300799 else None
    result = {'filename':filename,'summary':{'packets':count,'bytes':total_bytes,'duration_seconds':round(last-first,3) if first is not None else None,
             'start_utc':iso(first),'end_utc':iso(last),'unique_sources':len(sources),'unique_destinations':len(destinations),'parse_errors':parse_errors},
            'protocols':dict(protocols.most_common()),'top_sources':sources.most_common(12),'top_destinations':destinations.most_common(12),
            'top_ports':ports.most_common(12),'timeline':[{'minute':k,'count':v,'bytes':volume[k]} for k,v in sorted(timeline.items())[:500]],
            'packets':packets, 'connections':conversations.report(), 'connection_limit_reached':conversations.limited,
            'limitations':['Metadata-first parser; not full Wireshark protocol decoding.', 'All decoded packet metadata is searchable; the table shows 100 rows per page.',
                           'Bounded DNS, HTTP status/method and TLS record metadata only; no TCP reassembly, decryption or live capture.', 'TCP explanations use capture order; missing packets, reused ports and partial captures can limit conclusions.', 'Up to 200 TCP endpoint pairs and 80 events per pair are shown. Payload byte counts include repeated segments; fragmentation is excluded.']}

    from netsentry.investigation import enrich
    return enrich(result, config)
