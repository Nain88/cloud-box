from typing import Literal
from pydantic import BaseModel, Field, ConfigDict
import base64
from datetime import datetime, timezone
from .crypto import strict_json, sha

class WireEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["cbb.ingest/1.0"] = "cbb.ingest/1.0"
    boot_id: str = Field(min_length=1,max_length=64)
    source_seq: str = Field(pattern=r"^[0-9]{1,18}$")
    source_type: Literal["windows.event","windows.firewall","linux.journal","suricata.eve","zeek","fim","yara","acquisition","collector.health","lab.fixture"]
    event_type: str = Field(min_length=1,max_length=120)
    collected_at: str = Field(max_length=64)
    original_timestamp: str | None = Field(default=None,max_length=128)
    raw_media_type: str = Field(default="application/json",max_length=100)
    raw_base64: str = Field(max_length=90000)
    raw_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_cursor: dict = Field(default_factory=dict)

def parse_time(value):
    if not value: return None
    try:
        dt=datetime.fromisoformat(str(value).replace("Z","+00:00"))
        if not dt.tzinfo: return None
        return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")
    except (ValueError,TypeError): return None

def normalize(wire, collector, evidence_id, received_at, raw_ref):
    raw=base64.b64decode(wire["raw_base64"],validate=True)
    flags=[]; subject={}; details={}; severity=1; event_type=wire["event_type"]
    occurred=parse_time(wire.get("original_timestamp"))
    if occurred is None: flags.append("UNKNOWN_EVENT_TIME")
    if wire['source_type'] == 'windows.firewall':
        from .firewall import parse_record
        try:
            details = parse_record(raw, wire.get('source_cursor', {}).get('fields', []))
            action = details['action'].lower()
            event_type = 'firewall.' + action
            severity = 2 if action == 'drop' else 1
            subject = {'src_ip': details['src-ip'], 'dst_ip': details['dst-ip'], 'src_port': details.get('src-port'), 'dst_port': details.get('dst-port'), 'action': action, 'protocol': details.get('protocol')}
            details['summary'] = 'Windows Firewall ' + action + ': ' + details['src-ip'] + ' → ' + details['dst-ip'] + ':' + details.get('dst-port', '-')
        except (ValueError, KeyError, UnicodeError):
            flags.append('PARSE_ERROR')
            event_type = 'firewall.unparsed'
    elif "json" in wire["raw_media_type"]:
        try:
            data=strict_json(raw)
            if not isinstance(data,dict): data={"value":data}
            details=data
        except (ValueError,UnicodeError):
            flags.append("PARSE_ERROR");data={}
        if wire["source_type"] == "suricata.eve":
            event_type="network."+str(data.get("event_type","unknown"))
            subject={"src_ip":data.get("src_ip"),"dst_ip":data.get("dest_ip"),"src_port":data.get("src_port"),"dst_port":data.get("dest_port"),"flow_id":str(data.get("flow_id",""))}
            if isinstance(data.get("alert"),dict): severity={1:5,2:4,3:3}.get(data["alert"].get("severity"),2)
            occurred=parse_time(data.get("timestamp")) or occurred
        elif wire['source_type']=='zeek':
            from pathlib import PureWindowsPath
            kind=PureWindowsPath(str(wire.get('source_cursor',{}).get('path',''))).stem
            if kind not in {'conn','http','dns','ssl','notice'}:kind='observation'
            event_type='zeek.'+kind
            subject={key:data[field] for key,field in {'src_ip':'id.orig_h','dst_ip':'id.resp_h','src_port':'id.orig_p','dst_port':'id.resp_p','uid':'uid','protocol':'proto'}.items() if field in data}
            try:
                occurred=parse_time(datetime.fromtimestamp(float(data['ts']),timezone.utc).isoformat())
            except (KeyError,ValueError,TypeError,OverflowError,OSError):pass
            if occurred and 'UNKNOWN_EVENT_TIME' in flags:flags.remove('UNKNOWN_EVENT_TIME')
            details['summary']=f"Zeek {kind}: {subject.get('src_ip','?')} → {subject.get('dst_ip','?')} ({subject.get('uid','unknown UID')})"
        else:
            subject={k:data.get(k) for k in ("user","process","process_guid","pid","parent","path","src_ip","dst_ip","dst_port","action") if k in data}
            severity=max(0,min(5,int(data.get("severity",1))))
            if wire["source_type"]=="linux.journal":
                message=str(data.get("MESSAGE",data.get("message","")))
                if "Failed password" in message or "authentication failure" in message:event_type="auth.failure";severity=3
                details["message"]=message
    elif "xml" in wire["raw_media_type"]:
        import xml.etree.ElementTree as ET
        try:
            if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():raise ValueError("XML entities and DTDs are not allowed")
            root=ET.fromstring(raw)
            for e in root.iter():
                if e.tag.endswith("Data") and e.attrib.get("Name"): details[e.attrib["Name"]]=(e.text or "")[:8192]
                if e.tag.endswith("EventID"): details["event_id"]=e.text
                if e.tag.endswith("Provider"):details["provider"]=e.attrib.get("Name","")
                if e.tag.endswith("TimeCreated"): occurred=parse_time(e.attrib.get("SystemTime")) or occurred
            subject={"process":details.get("Image") or details.get("NewProcessName"),"process_guid":details.get("ProcessGuid"),"pid":details.get("ProcessId"),"parent":details.get("ParentImage"),"user":details.get("User") or details.get("SubjectUserName"),"dst_ip":details.get("DestinationIp"),"path":details.get("TargetFilename") or details.get("TargetObject")}
            mappings={"4688":"process.create","1102":"log.clear","104":"log.clear"}
            if details.get('provider') == 'Microsoft-Windows-Security-Auditing':
                mappings.update({'4625':'auth.failure','4624':'auth.success','5157':'firewall.drop','5152':'firewall.drop'})
                if details.get('event_id') == '4625':severity=3
            if "sysmon" in details.get("provider","").lower():mappings.update({"1":"process.create","3":"network.connect","11":"file.create","13":"registry.change"})
            event_type=mappings.get(details.get("event_id"),event_type)
            if event_type=="log.clear":severity=4
        except ET.ParseError:flags.append("PARSE_ERROR")
    else:
        message=raw.decode("utf-8",errors="replace")
        details={"message":message[:8192]}
        if "Failed password" in message or "authentication failure" in message: event_type="auth.failure";severity=3
    # Only bounded normalized fields enter the envelope; raw bytes remain authoritative.
    alert=details.get("alert") if isinstance(details.get("alert"),dict) else {}
    summary=str(details.get("summary") or alert.get("signature") or details.get("message") or event_type)[:300]
    return {"schema_version":"cbb.evidence/1.0","evidence_id":evidence_id,"collector_id":collector["id"],"asset_id":collector["asset_id"],"boot_id":wire["boot_id"],"source_seq":wire["source_seq"],"source_type":wire["source_type"],"event_type":event_type,"occurred_at":occurred,"original_timestamp":wire.get("original_timestamp"),"collected_at":wire["collected_at"],"received_at":received_at,"time_quality":{"parsed":occurred is not None},"severity":severity,"subject":subject,"summary":summary,"parser":{"name":wire["source_type"],"version":"1.0.0"},"raw":raw_ref,"provenance":{"source_cursor":wire.get("source_cursor",{})},"quality_flags":flags}
