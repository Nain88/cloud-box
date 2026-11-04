import base64
import json
from cbb.schema import normalize


def test_zeek_conn_preserves_source_time_uid_and_endpoints():
    raw=json.dumps({'ts':1700000000.25,'uid':'C123','id.orig_h':'127.0.0.1','id.resp_h':'127.0.0.1','id.resp_p':8080,'proto':'tcp'}).encode()
    wire={'raw_base64':base64.b64encode(raw).decode(),'source_type':'zeek','raw_media_type':'application/json','source_cursor':{'path':r'C:\logs\conn.log'},'event_type':'network.observation','boot_id':'b','source_seq':'1','collected_at':'2026-11-04T00:00:00Z'}
    event=normalize(wire,{'id':'collector','asset_id':'host'},'e1',wire['collected_at'],{})
    assert event['event_type']=='zeek.conn' and event['occurred_at']=='2023-11-14T22:13:20.250Z'
    assert 'UNKNOWN_EVENT_TIME' not in event['quality_flags']
    assert event['subject']['uid']=='C123' and event['subject']['dst_port']==8080
