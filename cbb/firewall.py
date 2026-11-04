"""Windows Firewall W3C records: original bytes remain the evidence source."""
import ipaddress


def parse_record(raw, fields):
    values = raw.decode('utf-8', errors='strict').strip().split()
    if not isinstance(fields,list) or not 1<=len(fields)<=64 or not all(isinstance(field,str) for field in fields) or len(values)!=len(fields):
        raise ValueError('Firewall record does not match its #Fields header')
    record = dict(zip(fields, values))
    if record.get('action') not in {'DROP', 'ALLOW'}:
        raise ValueError('Unsupported firewall action')
    for name in ('src-ip', 'dst-ip'):
        ipaddress.ip_address(record[name])
    for name in ('src-port', 'dst-port'):
        if record.get(name, '-') != '-':
            if not 0 <= int(record[name]) <= 65535:
                raise ValueError('Invalid firewall port')
    return record


def tail_firewall(agent, path):
    from pathlib import Path
    from .agent import MAX_EVENT
    from .crypto import canon
    path = Path(path).resolve()
    key = 'windows.firewall:' + str(path)
    cursor = agent.spool.get(key, {})
    stat = path.stat()
    identity = f'{stat.st_dev}:{stat.st_ino}'
    offset = int(cursor.get('offset', 0))
    fields = cursor.get('fields', [])
    timezone = cursor.get('timezone', 'UNKNOWN')
    if cursor.get('identity') != identity or stat.st_size < offset:
        if cursor:
            agent.spool.enqueue(canon({'summary': 'Firewall log rotated or truncated; unread old bytes may be unavailable', 'severity': 2}), 'collector.health', 'source.rotation')
        offset, fields, timezone = 0, [], 'UNKNOWN'
    with path.open('rb') as source:
        source.seek(offset)
        for _ in range(200):
            raw = source.readline(MAX_EVENT + 1)
            if not raw or not raw.endswith(b'\n'):
                if len(raw) > MAX_EVENT:
                    raise ValueError('Firewall line exceeds 64 KiB; cursor retained')
                break
            if len(raw) > MAX_EVENT:
                raise ValueError('Firewall line exceeds 64 KiB; cursor retained')
            text = raw.decode('utf-8', errors='replace').strip()
            if text.startswith('#Fields:'):
                fields = text[len('#Fields:'):].split()
            elif text.startswith('#Time Format:'):
                timezone = text.split(':', 1)[1].strip()
            next_cursor = {'path': str(path), 'identity': identity, 'offset': source.tell(), 'fields': fields, 'timezone': timezone}
            if not text or text.startswith('#'):
                agent.spool.set(key, next_cursor)
                continue
            try:
                record = parse_record(raw, fields)
            except (ValueError, KeyError):
                # Preserve malformed/unknown vendor rows and continue at the
                # next complete line. Normalization marks this record unparsed.
                agent.spool.enqueue(raw, 'windows.firewall', 'firewall.unparsed', 'text/plain', cursor=next_cursor, cursor_key=key)
                continue
            # Windows local wall-clock timestamps are ambiguous at DST changes.
            # Preserve that timestamp without inventing a timezone.
            stamp = record.get('date', '') + 'T' + record.get('time', '')
            if timezone.upper() in {'UTC', 'GMT'}:
                stamp += 'Z'
            agent.spool.enqueue(raw, 'windows.firewall', 'firewall.' + record['action'].lower(), 'text/plain', original_timestamp=stamp, cursor=next_cursor, cursor_key=key)
