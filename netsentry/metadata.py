"""Bounded application metadata decoding. Never executes or fetches captured content."""
import struct


def dns_message(data):
    if len(data) < 12:
        return {}
    _, flags, questions, answers, _, _ = struct.unpack_from('!6H', data)
    result = {'dns_response': bool(flags & 0x8000), 'dns_rcode': flags & 15, 'dns_answers': answers}
    if not questions:
        return result
    labels, pos, seen = [], 12, set()
    end = None
    for _ in range(128):
        if pos >= len(data) or pos in seen:
            return result
        seen.add(pos)
        size = data[pos]; pos += 1
        if size & 0xc0 == 0xc0:
            if pos >= len(data): return result
            if end is None: end = pos + 1
            pos = ((size & 63) << 8) | data[pos]
            continue
        if size == 0:
            end = end or pos
            break
        if size > 63 or pos + size > len(data): return result
        labels.append(data[pos:pos+size].decode('ascii', 'replace'))
        pos += size
    else:
        return result
    if end + 4 <= len(data):
        result.update(dns_query='.'.join(labels)[:253].lower(), dns_type=struct.unpack_from('!H', data, end)[0])
    return result


def application(data, sport, dport):
    result = {}
    if sport == 53 or dport == 53:
        if len(data) >= 2:
            length = int.from_bytes(data[:2], 'big')
            if length <= len(data)-2: result.update(dns_message(data[2:2+length]))
    line = data[:256].split(b'\r\n', 1)[0]
    if line.startswith((b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'OPTIONS ', b'HTTP/1.')):
        # Retain method/status only, never URL, credentials or header values.
        parts = line.decode('ascii', 'replace').split(' ')
        result['http'] = ' '.join(parts[:2]) if parts[0].startswith('HTTP/') else parts[0]
        if parts[0].startswith('HTTP/') and len(parts) > 1:
            result['auth_failure'] = parts[1] == '401'
    if sport == 21 and line.startswith(b'530 '): result['auth_failure'] = True
    if len(data) >= 5 and data[0] in (20,21,22,23) and data[1] == 3 and data[2] <= 4:
        result['tls'] = {'record_type': data[0], 'legacy_record_version': f'3.{data[2]}', 'record_length': int.from_bytes(data[3:5], 'big')}
    return result
