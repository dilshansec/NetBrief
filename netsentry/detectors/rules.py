"""Independent heuristic rules. Each yields (packets, indicators, confidence)."""
from collections import defaultdict, Counter
import math
import statistics


def groups(rows, key, seconds=None):
    out = defaultdict(list)
    for p in rows:
        if seconds and p.get('timestamp') is None: continue
        k = key(p)
        if seconds: k = (k, int(p['timestamp']//seconds))
        out[k].append(p)
    return out.values()


def attempts(p):
    return p['protocol']=='TCP' and 'SYN' in p['flags'] and 'ACK' not in p['flags']


def tcp_outcomes(rows):
    """Match observed SYN/SYNACK/final ACK by endpoint and sequence numbers."""
    syns={}; offered={}; responded=set(); completed=set()
    for p in rows:
        if p['protocol']!='TCP' or p.get('seq') is None:continue
        src,dst,sp,dp=p['src'],p['dst'],p['sport'],p['dport']
        if attempts(p):
            syns[(src,dst,sp,dp,p['seq'])]=p['no']
        elif 'SYN' in p['flags'] and 'ACK' in p['flags']:
            key=(dst,src,dp,sp,(p['ack_number']-1)%2**32)
            if key in syns:
                number=syns[key];responded.add(number)
                offered[(dst,src,dp,sp,p['ack_number'],(p['seq']+1)%2**32)]=number
        elif 'ACK' in p['flags'] and 'RST' not in p['flags']:
            key=(src,dst,sp,dp,p['seq'],p['ack_number'])
            if key in offered:completed.add(offered[key])
    return responded,completed


def port_scan(rows, c):
    responded,completed=tcp_outcomes(rows)
    candidates=[p for p in rows if attempts(p) or (p['protocol']=='TCP' and (not p['flags'] or set(p['flags'])=={'FIN'} or {'FIN','PSH','URG'}<=set(p['flags']))) or p['protocol']=='UDP']
    for g in groups(candidates,lambda p:p['src'],c.window_seconds):
        ports={p['dport'] for p in g}; hosts={p['dst'] for p in g}
        if len(ports)>=c.scan_ports or len(hosts)>=c.discovery_hosts:
            yield g, {'unique_ports':len(ports),'unique_hosts':len(hosts),'patterns':sorted({','.join(p['flags']) or p['protocol']+' NULL/empty flags' for p in g}), 'threshold':c.scan_ports,'host_threshold':c.discovery_hosts,'matching_synack_attempts':sum(p['no'] in responded for p in g),'completed_handshakes':sum(p['no'] in completed for p in g)}, 'medium'


def host_discovery(rows,c):
    for g in groups([p for p in rows if p.get('icmp_type') in (8,128) or p.get('arp_op')==1 or attempts(p)],lambda p:p['src'],c.window_seconds):
        hosts=len({p['dst'] for p in g})
        if hosts>=c.discovery_hosts:
            yield g, {'unique_targets':hosts,'threshold':c.discovery_hosts}, 'medium'


def syn_flood(rows,c):
    responded,completed=tcp_outcomes(rows)
    replies=Counter((p['src'],p['sport'],int(p['timestamp']//c.window_seconds)) for p in rows if p.get('timestamp') is not None and 'SYN' in p['flags'] and 'ACK' in p['flags'])
    for g in groups([p for p in rows if attempts(p)],lambda p:(p['dst'],p['dport']),c.window_seconds):
        p=g[0]; response=replies[(p['dst'],p['dport'],int(p['timestamp']//c.window_seconds))]
        if len(g)>=c.syn_packets and response/max(1,len(g))<.2:
            yield g, {'syn_count':len(g),'observed_synack_count':response,'synack_ratio':round(response/len(g),3),'threshold':c.syn_packets,'matching_synack_attempts':sum(p['no'] in responded for p in g),'completed_handshakes':sum(p['no'] in completed for p in g),'completed_handshake_ratio':round(sum(p['no'] in completed for p in g)/len(g),3)}, 'medium'


def brute_force(rows,c):
    for g in groups([p for p in rows if (attempts(p) and p['dport'] in (21,22,23,80,443,3389)) or p.get('auth_failure')],lambda p:(p['dst'],p['src'],p['sport']) if p.get('auth_failure') else (p['src'],p['dst'],p['dport']),c.window_seconds):
        failures=sum(bool(p.get('auth_failure')) for p in g)
        connections=len({(p['src'],p['sport'],p.get('seq')) for p in g if attempts(p)})
        if max(failures,connections)>=c.brute_connections:
            yield g, {'distinct_connection_attempts':connections,'observed_failure_responses':failures,'threshold':c.brute_connections}, 'medium' if failures else 'low'


def arp_spoofing(rows,c):
    for g in groups([p for p in rows if p.get('arp_mac') and p['src']!='0.0.0.0'],lambda p:p['src'],c.window_seconds):
        macs=sorted({p['arp_mac'] for p in g})
        if len(macs)>=c.arp_changes:
            yield g, {'claiming_macs':macs,'threshold':c.arp_changes}, 'medium'


def entropy(value):
    return -sum((n/len(value))*math.log2(n/len(value)) for n in Counter(value).values()) if value else 0


def dns_tunneling(rows,c):
    for g in groups([p for p in rows if p.get('dns_query') and not p.get('dns_response')],lambda p:(p['src'],'.'.join(p['dns_query'].split('.')[-2:])),c.window_seconds):
        names={p['dns_query'] for p in g}; suspicious=[n for n in names if len(n.split('.')[0])>=32 and entropy(n.split('.')[0])>=3.5]
        if len(suspicious)>=c.dns_queries:
            yield g, {'unique_queries':len(names),'long_high_entropy_queries':len(suspicious),'parent_domain':'.'.join(g[0]['dns_query'].split('.')[-2:]),'threshold':c.dns_queries}, 'low'


def icmp_flood(rows,c):
    for g in groups([p for p in rows if p.get('icmp_type') in (8,128)],lambda p:p['dst'],c.window_seconds):
        if len(g)>=c.icmp_packets:
            yield g, {'echo_requests':len(g),'requests_per_window_second':round(len(g)/c.window_seconds,2),'threshold':c.icmp_packets}, 'medium'


def exfiltration(rows,c):
    import ipaddress
    nets=[ipaddress.ip_network(n) for n in c.internal_networks]
    def internal(ip):
        try:return any(ipaddress.ip_address(ip) in n for n in nets)
        except ValueError:return False
    outgoing=[p for p in rows if internal(p['src']) and not internal(p['dst']) and p['dst']!='—' and not ipaddress.ip_address(p['dst']).is_multicast and p['protocol']!='ARP']
    inbound=Counter()
    for p in rows: inbound[(p['dst'],p['src'])]+=p['captured_length']
    for g in groups(outgoing,lambda p:(p['src'],p['dst'])):
        size=sum(p['captured_length'] for p in g); received=inbound[(g[0]['src'],g[0]['dst'])]
        if size>=c.exfil_bytes and size/max(1,received)>=5:
            yield g, {'outbound_captured_bytes':size,'inbound_captured_bytes':received,'ratio':round(size/max(1,received),2),'threshold':c.exfil_bytes,'baseline':'unavailable'}, 'low'


def beaconing(rows,c):
    for g in groups([p for p in rows if attempts(p) and p.get('timestamp') is not None],lambda p:(p['src'],p['dst'],p['dport'])):
        unique={ (p['sport'],p.get('seq')):p for p in g }
        evidence=sorted(unique.values(),key=lambda p:p['timestamp'])
        times=[p['timestamp'] for p in evidence]; gaps=[b-a for a,b in zip(times,times[1:])]
        if len(evidence)>=c.beacon_connections and gaps and min(gaps)>=1 and times[-1]-times[0]>=60:
            mean=statistics.mean(gaps); jitter=statistics.pstdev(gaps)/mean
            if jitter<=.15:
                yield evidence, {'connections':len(evidence),'mean_interval_seconds':round(mean,3),'interval_cv':round(jitter,3),'threshold':c.beacon_connections}, 'low'

RULES={
 'port_scan':(port_scan,'Potential port scan','medium','T1046','Authorized scanning, service discovery or application fan-out.'),
 'host_discovery':(host_discovery,'Host discovery indicators','low','T1018','Normal inventory tools, ARP discovery or monitoring.'),
 'syn_flood':(syn_flood,'Potential SYN flood','high','T1498','Load tests, retransmissions, traffic bursts or asymmetric capture.'),
 'brute_force':(brute_force,'Repeated authentication-service connections','medium','T1110','Automated jobs, reconnecting clients or service health checks.'),
 'arp_spoofing':(arp_spoofing,'Conflicting ARP address claims','high','T1557.002','Failover, proxy ARP, DHCP changes, virtualization or device replacement.'),
 'dns_tunneling':(dns_tunneling,'DNS tunneling indicators','medium','T1071.004','CDNs, security products, cloud telemetry or encoded tracking names.'),
 'icmp_flood':(icmp_flood,'Potential ICMP flood','high','T1498','Diagnostics, monitoring or authorized load testing.'),
 'exfiltration':(exfiltration,'Large outbound transfer','medium',None,'Backups, cloud synchronization or ordinary uploads.'),
 'beaconing':(beaconing,'Periodic connection indicators','medium','T1071','Heartbeats, update agents, monitoring or telemetry.'),
}
