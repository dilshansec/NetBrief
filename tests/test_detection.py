import struct
import unittest
from unittest.mock import patch
from netsentry.parser import analyze, decode, CaptureError
from netsentry.config import Settings
from netsentry.metadata import dns_message
from samples.lab import generate, NAMES, MIXED_CATEGORIES
from samples.make_conversation import records, capture, packet

class DetectionTests(unittest.TestCase):
    def test_each_category_has_real_evidence(self):
        for name in NAMES:
            with self.subTest(name=name):
                r=analyze(generate(name),name)
                if name=='normal':self.assertEqual(r['alerts'],[]);continue
                if name=='mixed':
                    self.assertEqual({a['category'] for a in r['alerts']},set(MIXED_CATEGORIES))
                    self.assertEqual(len(r['alerts']),4)
                    self.assertEqual(r['summary']['packets'],321)
                    self.assertEqual(r['summary']['unique_hosts'],5)
                    self.assertEqual(len({tuple(sorted((f['a'],f['b']))) for f in r['flows']}),3)
                    self.assertEqual(set(r['protocols']),{'TCP','ARP','DNS','ICMP'})
                    self.assertEqual(sum(a['severity']=='high' for a in r['alerts']),2)
                alerts=[a for a in r['alerts'] if name=='mixed' or a['category']==name]
                self.assertTrue(alerts)
                for a in alerts:
                    ids={p['no'] for p in r['packets']}
                    self.assertTrue(set(a['packet_numbers'])<=ids)
                    self.assertTrue(a['flow_ids'])
                    self.assertNotEqual(a['confidence'],'high')
                    self.assertTrue(a['benign_explanations'])

    def test_scan_boundary_and_disabled_rule(self):
        r=analyze(generate('port_scan'),'scan',{'scan_ports':31})
        self.assertFalse(any(a['category']=='port_scan' for a in r['alerts']))
        r=analyze(generate('port_scan'),'scan',{'scan_ports':30})
        self.assertTrue(any(a['category']=='port_scan' for a in r['alerts']))
        r=analyze(generate('port_scan'),'scan',{'disabled_rules':['port_scan']})
        self.assertFalse(r['alerts'])
        self.assertEqual(r['coverage'][0]['status'],'disabled')

    def test_allowlists_do_not_hide_alerts(self):
        r=analyze(generate('port_scan'),'scan',{'authorized_scanners':['10.0.0.10']})
        self.assertTrue(r['alerts'][0]['allowlist_notes'])

    def test_brute_retransmissions_not_connections(self):
        raw=packet('10.0.0.10','198.51.100.20',40000,22,100,0,2)
        r=analyze(capture([raw]*30),'retransmissions')
        self.assertFalse(any(a['category']=='brute_force' for a in r['alerts']))

    def test_encrypted_auth_is_indirect(self):
        a=next(a for a in analyze(generate('brute_force'),'ssh')['alerts'] if a['category']=='brute_force')
        self.assertEqual(a['confidence'],'low')
        self.assertEqual(a['indicators']['observed_failure_responses'],0)

    def test_dns_compression_loop(self):
        self.assertNotIn('dns_query',dns_message(struct.pack('!6H',1,0,1,0,0,0)+b'\xc0\x0c'))

    def test_settings_validation(self):
        for value in ({'window_seconds':0},{'internal_networks':['bad']},{'disabled_rules':['bad']},{'scan_ports':-1}):
            with self.assertRaises(ValueError):Settings.model_validate(value)

    def test_empty_capture(self):
        r=analyze(capture([]),'empty')
        self.assertEqual(r['summary']['packets'],0)
        self.assertFalse(r['alerts'])

    def test_invalid_and_truncated(self):
        for data in (b'bad',generate('normal')[:-4],generate('normal')[:30]):
            with self.assertRaises(CaptureError):analyze(data,'bad')

    def test_packet_limit(self):
        with patch('netsentry.parser.MAX_PACKETS',2):
            with self.assertRaises(CaptureError):analyze(generate('normal'),'over-limit')

    def test_ipv6_icmp(self):
        import ipaddress
        header=struct.pack('!IHBB',6<<28,8,58,64)+ipaddress.ip_address('fd00::1').packed+ipaddress.ip_address('fd00::2').packed
        d=decode(101,header+struct.pack('!BBHI',128,0,0,1))
        self.assertEqual(d['src'],'fd00::1');self.assertEqual(d['icmp_type'],128)

    def test_http_metadata(self):
        d=decode(1,records()[3]);self.assertEqual(d['http'],'GET')
        self.assertNotIn('/demo',str(d))

    def test_pcapng(self):
        def block(kind,body):
            body+=b'\0'*((-len(body))%4);size=12+len(body)
            return struct.pack('<II',kind,size)+body+struct.pack('<I',size)
        raw=records()[0]
        data=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',1,0,65535))+block(6,struct.pack('<IIIII',0,0,1000000,len(raw),len(raw))+raw)
        r=analyze(data,'test.pcapng')
        self.assertEqual(r['summary']['packets'],1)
        self.assertEqual(r['packets'][0]['timestamp'],1)
        with self.assertRaises(CaptureError):analyze(data[:-1],'truncated')

    def test_short_packet_kept_visible(self):
        r=analyze(capture([b'\0'*5]),'short')
        self.assertEqual(r['packets'][0]['protocol'],'OTHER')

    def test_byte_totals_and_flow_directions(self):
        r=analyze(generate('normal'),'normal')
        self.assertEqual(sum(f['bytes'] for f in r['flows']),r['summary']['captured_bytes'])
        self.assertTrue(any(f['a_to_b_bytes'] and f['b_to_a_bytes'] for f in r['flows']))

if __name__=='__main__':unittest.main()

class BenignBoundaryTests(unittest.TestCase):
    def test_thresholds_above_fixture_do_not_trigger_category(self):
        configs={'host_discovery':{'discovery_hosts':31},'syn_flood':{'syn_packets':251},'brute_force':{'brute_connections':26},'arp_spoofing':{'arp_changes':3},'dns_tunneling':{'dns_queries':26},'icmp_flood':{'icmp_packets':251},'exfiltration':{'exfil_bytes':6000000},'beaconing':{'beacon_connections':11}}
        for category,config in configs.items():
            with self.subTest(category=category):
                self.assertFalse(any(a['category']==category for a in analyze(generate(category),category,config)['alerts']))

    def test_observed_synack_responses_reduce_flood_signal(self):
        from netsentry.detectors.rules import syn_flood
        r=analyze(generate('syn_flood'),'flood')
        rows=r['packets']
        replies=[dict(p,src=p['dst'],dst=p['src'],sport=p['dport'],dport=p['sport'],flags=['SYN','ACK']) for p in rows]
        self.assertEqual(list(syn_flood(rows+replies,Settings())),[])

    def test_timing_jitter_rejects_beacon(self):
        from netsentry.detectors.rules import beaconing
        rows=analyze(generate('beaconing'),'beacon')['packets']
        for i,p in enumerate(rows):p['timestamp']+=i*i*20
        self.assertEqual(list(beaconing(rows,Settings())),[])

    def test_short_dns_names_not_tunneling(self):
        from netsentry.detectors.rules import dns_tunneling
        rows=analyze(generate('dns_tunneling'),'dns')['packets']
        for i,p in enumerate(rows):p['dns_query']=f'cdn{i}.example.test'
        self.assertEqual(list(dns_tunneling(rows,Settings())),[])

class OutcomeTests(unittest.TestCase):
    def test_matches_full_handshake_and_rejects_wrong_ack(self):
        from netsentry.detectors.rules import tcp_outcomes
        rows=analyze(generate('normal'),'normal')['packets'][:3]
        responded,completed=tcp_outcomes(rows)
        self.assertIn(1,responded);self.assertIn(1,completed)
        rows[2]['ack_number']=999
        self.assertNotIn(1,tcp_outcomes(rows)[1])
