"""Local sensor liveness observations, not remote attestation."""
import json
from pathlib import Path
from datetime import datetime,timezone

def input_health(paths):
    result=[]
    for value in paths:
        path=Path(value);item={"path":str(path),"state":"MISSING"}
        try:
            stat=path.stat();item.update(state="READABLE",bytes=stat.st_size,modified_at=datetime.fromtimestamp(stat.st_mtime,timezone.utc).isoformat())
            with path.open("rb") as stream:stream.read(1)
            status=path.parent/"sensor-status.json"
            if status.is_file() and status.stat().st_size<=32768:
                sensor=json.loads(status.read_text(encoding="utf-8"))
                age=(datetime.now(timezone.utc)-datetime.fromisoformat(sensor["updated_at"])).total_seconds()
                item["sensor"]={**sensor,"status_age_seconds":round(age),"fresh":0<=age<30}
        except FileNotFoundError:item["state"]="MISSING"
        except (OSError,ValueError,KeyError):item["state"]="UNREADABLE_OR_INVALID_STATUS"
        result.append(item)
    return result
