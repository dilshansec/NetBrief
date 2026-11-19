"""Bounded, evidence-based TCP conversation summaries; no payload retention."""
class Conversations:
    def __init__(self):
        self.items = {}
        self.limited = False

    def add(self, p, number, timestamp):
        if p.get('seq') is None:
            return
        src, dst = (p['src'], p['sport']), (p['dst'], p['dport'])
        key = tuple(sorted((src, dst)))
        if key not in self.items:
            if len(self.items) >= 200:
                self.limited = True
                return
            self.items[key] = dict(id=len(self.items), groups={'syn':[], 'data':[], 'close':[], 'reset':[]}, a=src, b=dst, packets=0, bytes=[0, 0], events=[],
                syn=None, synack=None, handshake=None, reset=False, fins={}, fin_acks=set(),
                repeats=0, seen=set(), truncated=False, reused=False)
        c = self.items[key]
        direction = 0 if src == c['a'] else 1
        flags = p['flags']; seq = p['seq']; ack = p['ack_number']; size = p['payload_bytes']
        c['packets'] += 1
        c['bytes'][direction] += size
        c['truncated'] |= p['truncated']
        text = 'Acknowledges received TCP bytes.' if 'ACK' in flags else 'TCP segment observed.'
        kind = 'ACK'
        if 'SYN' in flags and 'ACK' not in flags:
            kind = 'SYN'; text = 'Requests a TCP connection. A reply is needed before establishment can be confirmed.'
            if c['syn'] is None:
                c['syn'] = (direction, seq, number, timestamp)
            elif c['syn'][:2] != (direction, seq):
                c['reused'] = True
        elif 'SYN' in flags and 'ACK' in flags:
            kind = 'SYN / ACK'; text = 'Offers a TCP connection and acknowledges a SYN.'
            syn = c['syn']
            if syn and direction != syn[0] and ack == (syn[1] + 1) % 2**32:
                c['synack'] = (seq, number, timestamp)
        elif 'ACK' in flags and c['syn'] and c['synack'] and c['handshake'] is None:
            syn, sa = c['syn'], c['synack']
            if direction == syn[0] and seq == (syn[1]+1) % 2**32 and ack == (sa[0]+1) % 2**32 and 'RST' not in flags:
                c['handshake'] = (number, timestamp)
                kind = 'Handshake ACK'; text = 'Completes the observed SYN -> SYN/ACK -> ACK exchange. TCP is established.'
        if 'SYN' in flags:
            c['groups']['syn'].append(number)
        if size:
            c['groups']['data'].append(number)
            kind += ' + DATA'; text += f' Carries {size} captured application bytes; content is not decoded.'
            signature = (direction, seq, size)
            if signature in c['seen']:
                c['repeats'] += 1
                text += ' Same sequence and length appeared earlier: possible retransmission or duplicate capture.'
            if len(c['seen']) < 10000:
                c['seen'].add(signature)
        if 'FIN' in flags:
            c['groups']['close'].append(number)
            c['fins'][direction] = (seq + size + 1) % 2**32
            kind = 'FIN / ACK' if 'ACK' in flags else 'FIN'
            text = 'This endpoint asks to finish its sending side of the connection.'
        if 'ACK' in flags and c['fins'].get(1-direction) == ack:
            c['fin_acks'].add(1-direction)
            if number not in c['groups']['close'][-1:]: c['groups']['close'].append(number)
        if 'RST' in flags:
            c['groups']['reset'].append(number)
            c['reset'] = True; kind = 'RST'; text = 'An endpoint reset the connection. The packet alone does not establish the cause.'
        if len(c['events']) < 80:
            c['events'].append(dict(packet=number, time=timestamp, direction=direction,
                kind=kind, explanation=text, flags=flags, seq=seq, ack=ack, payload_bytes=size))

        return c['id']

    def report(self):
        result = []
        for c in self.items.values():
            syn, sa, hs = c['syn'], c['synack'], c['handshake']
            handshake = 'Complete handshake observed' if hs else 'Partial handshake observed' if syn or sa else 'Handshake not captured'
            close = 'Reset observed' if c['reset'] else 'Both FINs acknowledged' if len(c['fin_acks']) == 2 else 'Close started; completion not observed' if c['fins'] else 'Connection close not captured'
            notes = []
            if not hs:
                notes.append('Missing handshake packets do not prove failure: capture may start late, omit a direction, or lose packets.')
            if c['truncated']:
                notes.append('Some packets were truncated; byte totals describe captured payload only.')
            if c['reused']:
                notes.append('Multiple connection attempts share these endpoints. This summary groups them; inspect individual packets.')
            if c['repeats']:
                notes.append('Repeated sequence/length is a heuristic, not proof of network loss. Only the first 10,000 data signatures are tracked.')
            a, b = c['a'], c['b']
            ip = 'ipv6' if ':' in a[0] else 'ip'
            filt = f'tcp && (({ip}.src == {a[0]} && tcp.srcport == {a[1]} && {ip}.dst == {b[0]} && tcp.dstport == {b[1]}) || ({ip}.src == {b[0]} && tcp.srcport == {b[1]} && {ip}.dst == {a[0]} && tcp.dstport == {a[1]}))'
            elapsed = None
            if hs and syn[3] is not None and hs[1] is not None and hs[1] >= syn[3]:
                elapsed = round((hs[1]-syn[3])*1000, 3)
            groups=[]
            if hs:
                groups.append(dict(name='TCP handshake', packets=[syn[2],sa[1],hs[0]], description='SYN, matching SYN/ACK, and final ACK observed.'))
            elif c['groups']['syn']:
                groups.append(dict(name='TCP setup (partial)', packets=c['groups']['syn'], description='Setup packets observed; the complete three-way exchange was not captured.'))
            for key,label,description in [('data','TCP data transfer','Packets containing captured TCP payload bytes.'),('close','TCP connection close','FIN packets and observed acknowledgments of FIN.'),('reset','TCP reset','Packets with the RST flag; no cause inferred.')]:
                if c['groups'][key]: groups.append(dict(name=label,packets=c['groups'][key],description=description))
            result.append(dict(id=c['id'], event_groups=groups, endpoint_a=f'{a[0]}:{a[1]}', endpoint_b=f'{b[0]}:{b[1]}',
                packets=c['packets'], payload_bytes_a_to_b=c['bytes'][0], payload_bytes_b_to_a=c['bytes'][1],
                handshake=handshake, handshake_packets=[syn[2],sa[1],hs[0]] if hs else [],
                handshake_ms=elapsed, close=close, possible_retransmissions=c['repeats'], notes=notes,
                events=c['events'], events_omitted=max(0,c['packets']-80), wireshark_filter=filt))
        return result
