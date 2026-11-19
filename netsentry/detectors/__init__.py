"""Evidence envelope and coverage for independent rule functions."""
from .rules import RULES


def detect(packets, config):
    alerts=[]; coverage=[]
    for category,(rule,title,severity,mitre,benign) in RULES.items():
        if category in config.disabled_rules:
            coverage.append({'category':category,'status':'disabled','alerts':0}); continue
        count=0
        for evidence,indicators,confidence in rule(packets,config):
            if count>=100: break
            ordered=sorted(evidence,key=lambda p:(p.get('timestamp') is None,p.get('timestamp') or 0))
            notes=[]
            sources=sorted({p['src'] for p in evidence}); destinations=sorted({p['dst'] for p in evidence})
            if set(sources)&set(config.trusted_hosts): notes.append('Includes a trusted host; alert retained for review.')
            if set(sources)&set(config.authorized_scanners): notes.append('Includes an authorized scanner; alert retained for review.')
            if any(p.get('dns_query')==d or p.get('dns_query','').endswith('.'+d) for p in evidence for d in config.allowlisted_domains): notes.append('Includes an allowlisted domain; alert retained for review.')
            count+=1
            alerts.append(dict(id=f'{category}-{count}',title=title,category=category,severity=severity,confidence=confidence,sources=sources,destinations=destinations,
                source_ports=sorted({p['sport'] for p in evidence if p['sport'] is not None}),destination_ports=sorted({p['dport'] for p in evidence if p['dport'] is not None}),
                first_seen=ordered[0]['time'],last_seen=ordered[-1]['time'],packet_numbers=[p['no'] for p in evidence[:1000]],evidence_total=len(evidence),
                flow_ids=sorted({p['flow_id'] for p in evidence if p.get('flow_id')}),indicators=indicators,rule=category,window_seconds=config.window_seconds,
                explanation=f'{title}: observed indicators met the configured rule. This is a heuristic finding, not a confirmed attack.',
                benign_explanations=[benign],recommendations=['Inspect supporting packets and reverse traffic.','Confirm host ownership and authorized activity.','Correlate with endpoint, authentication and network logs.'],
                limitations=['Partial/asymmetric captures can change this interpretation.','No established traffic baseline or payload reassembly.','Evidence references capped at 1,000 per alert; up to 100 alerts per rule.'],
                mitre_techniques=[mitre] if mitre else [],allowlist_notes=notes,status='New'))
        available=bool(packets)
        if category=='arp_spoofing':available=any(p.get('arp_mac') for p in packets)
        elif category=='dns_tunneling':available=any(p.get('dns_query') and not p.get('dns_response') for p in packets)
        elif category=='icmp_flood':available=any(p.get('icmp_type') in (8,128) for p in packets)
        elif category in ('syn_flood','brute_force','beaconing'):available=any(p['protocol']=='TCP' and p.get('timestamp') is not None for p in packets)
        coverage.append({'category':category,'status':'evaluated' if available else 'insufficient evidence','alerts':count})
    return alerts,coverage
