"""Host/flow inventory, deterministic evidence correlation and report enrichment."""
from collections import Counter
import ipaddress
from .config import Settings
from .detectors import detect


def enrich(report, config=None):
    c=Settings.model_validate(config or {})
    nets=[ipaddress.ip_network(n) for n in c.internal_networks]
    hosts={}; flows={}
    for p in report['packets']:
        if p['src']=='—' or p['dst']=='—': continue
        for side,other,mac in [('src','dst','src_mac'),('dst','src','dst_mac')]:
            ip=p[side]
            if ip not in hosts:
                hosts[ip]=dict(ip=ip,internal=any(ipaddress.ip_address(ip) in n for n in nets),macs=set(),sent_packets=0,received_packets=0,sent_bytes=0,received_bytes=0,peers=set(),ports=set(),protocols=Counter(),dns=set())
            h=hosts[ip]; prefix='sent' if side=='src' else 'received'
            h[prefix+'_packets']+=1; h[prefix+'_bytes']+=p['captured_length']
            h['peers'].add(p[other]);h['protocols'][p['protocol']]+=1
            if p.get(mac):h['macs'].add(p[mac])
            if p['dport'] is not None:h['ports'].add(p['dport'])
            if p.get('dns_query'):h['dns'].add(p['dns_query'])
        endpoints=sorted([(p['src'],p['sport'] or 0),(p['dst'],p['dport'] or 0)])
        key=(p['protocol'],*endpoints)
        if key not in flows:
            flows[key]=dict(id=f'flow-{len(flows)+1}',a=endpoints[0][0],a_port=endpoints[0][1],b=endpoints[1][0],b_port=endpoints[1][1],protocol=p['protocol'],packets=0,bytes=0,a_to_b_bytes=0,b_to_a_bytes=0,first_seen=None,last_seen=None)
        f=flows[key];p['flow_id']=f['id'];f['packets']+=1;f['bytes']+=p['captured_length']
        f['a_to_b_bytes' if (p['src'],p['sport'] or 0)==endpoints[0] else 'b_to_a_bytes']+=p['captured_length']
        if p['timestamp'] is not None:
            f['first_seen']=p['timestamp'] if f['first_seen'] is None else min(f['first_seen'],p['timestamp'])
            f['last_seen']=p['timestamp'] if f['last_seen'] is None else max(f['last_seen'],p['timestamp'])
    for f in flows.values():f['duration_seconds']=f['last_seen']-f['first_seen'] if f['first_seen'] is not None else None
    alerts,coverage=detect(report['packets'],c)
    for h in hosts.values():
        for k in ('macs','peers','ports','dns'):h[k]=sorted(h[k])
        h['protocols']=dict(h['protocols'])
        h['alert_ids']=[a['id'] for a in alerts if h['ip'] in a['sources'] or h['ip'] in a['destinations']]
    # Shared source and time bucket are a review grouping, never inferred causality.
    incidents={}
    for a in alerts:
        key=(tuple(a['sources']),a['first_seen'][:16] if a['first_seen'] else 'unknown')
        incidents.setdefault(key,[]).append(a['id'])
    report.update(hosts=list(hosts.values()),flows=list(flows.values()),alerts=alerts,coverage=coverage,settings=c.model_dump(),incidents=[{'id':f'incident-{i+1}','alert_ids':ids,'basis':'Shared source set and UTC minute; no causal relationship inferred.'} for i,ids in enumerate(incidents.values())])
    report['summary'].update(unique_hosts=len(hosts),flows=len(flows),security_events=len(alerts),captured_bytes=sum(p['captured_length'] for p in report['packets']))
    report['limitations'] += ['No alerts does not guarantee safety. All security detections are heuristics.','Fixed time buckets can split activity across window boundaries.','Allowlisted entities are annotated, never silently suppressed.','DNS parent grouping uses the last two labels, not a public-suffix database.']
    return report
