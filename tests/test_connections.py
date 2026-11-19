import unittest
import struct
from samples.make_conversation import capture, records, packet, checksum
from netsentry.parser import analyze, decode

class ConnectionTests(unittest.TestCase):
    def test_teaching_capture(self):
        report=analyze(capture(),'demo.pcap')
        self.assertEqual(report['summary']['packets'],16)
        self.assertEqual(len(report['connections']),3)
        good,partial,reset=report['connections']
        self.assertEqual(good['handshake_packets'],[1,2,3])
        self.assertEqual(good['handshake_ms'],40)
        self.assertEqual(good['close'],'Both FINs acknowledged')
        self.assertEqual(good['possible_retransmissions'],1)
        self.assertGreater(good['payload_bytes_a_to_b'],0)
        self.assertEqual(partial['handshake'],'Partial handshake observed')
        self.assertEqual(reset['close'],'Reset observed')

    def test_midstream_is_not_failed(self):
        c=analyze(capture(records()[3:8]),'partial.pcap')['connections'][0]
        self.assertEqual(c['handshake'],'Handshake not captured')
        self.assertTrue(c['notes'])

    def test_wrong_ack_cannot_complete_handshake(self):
        rows=records()[:2]+[packet('192.0.2.10','198.51.100.20',51524,80,1001,999,16)]
        c=analyze(capture(rows),'bad-ack.pcap')['connections'][0]
        self.assertEqual(c['handshake_packets'],[])

    def test_wrong_synack_cannot_complete_handshake(self):
        rows=[records()[0],packet('198.51.100.20','192.0.2.10',80,51524,5000,999,18),records()[2]]
        self.assertEqual(analyze(capture(rows),'bad.pcap')['connections'][0]['handshake_packets'],[])

    def test_padding_not_payload(self):
        p=decode(1,records()[0]+b'\0'*20)
        self.assertEqual(p['payload_bytes'],0)

    def test_short_tcp_header_not_trusted(self):
        self.assertNotIn('seq',decode(1,records()[0][:48]))

    def test_fragment_not_analyzed_as_connection(self):
        raw=bytearray(records()[0]);raw[20:22]=struct.pack('!H',0x2000)
        self.assertNotIn('seq',decode(1,bytes(raw)))

    def test_close_needs_both_acknowledgments(self):
        c=analyze(capture(records()[:11]),'partial-close.pcap')['connections'][0]
        self.assertEqual(c['close'],'Close started; completion not observed')

    def test_demo_checksums(self):
        for raw in records():
            self.assertEqual(checksum(raw[14:34]),0)
            tcp=raw[34:]; pseudo=raw[26:34]+struct.pack('!BBH',0,6,len(tcp))
            self.assertEqual(checksum(pseudo+tcp),0)

    def test_original_scan(self):
        from pathlib import Path
        r=analyze(Path('samples/demo_scan.pcap').read_bytes(),'scan.pcap')
        self.assertEqual(r['summary']['packets'],25)
        self.assertTrue(any(a['category']=='port_scan' for a in r['alerts']))

    def test_story_is_bounded(self):
        c=analyze(capture([records()[2]]*100),'many.pcap')['connections'][0]
        self.assertEqual(len(c['events']),80)
        self.assertEqual(c['events_omitted'],20)

    def test_interleaved_handshake_exact_frames(self):
        unrelated=packet('192.0.2.30','198.51.100.40',1234,80,1,0,2)
        rows=[records()[0],unrelated,records()[1],unrelated,records()[2]]
        r=analyze(capture(rows),'interleaved.pcap')
        self.assertEqual(r['connections'][0]['event_groups'][0]['packets'],[1,3,5])
        self.assertEqual([p['connection_id'] for p in r['packets']],[0,1,0,1,0])

    def test_events_and_packets_beyond_500(self):
        unrelated=packet('192.0.2.30','198.51.100.40',1234,80,1,0,2)
        r=analyze(capture([unrelated]*510+records()[:3]),'large.pcap')
        self.assertEqual(len(r['packets']),513)
        self.assertEqual(r['connections'][1]['event_groups'][0]['packets'],[511,512,513])

    def test_data_and_close_evidence(self):
        groups={g['name']:g['packets'] for g in analyze(capture(),'demo.pcap')['connections'][0]['event_groups']}
        self.assertEqual(groups['TCP data transfer'],[4,6,7])
        self.assertEqual(groups['TCP connection close'],[9,10,11,12])

if __name__=='__main__': unittest.main()
