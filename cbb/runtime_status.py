"""Read-only bounded host probes. Availability is distinct from capture coverage."""
import json
import os
import subprocess
import threading
import time
from pathlib import Path
import httpx
from .crypto import now
from .tooling import bounded_process, tool_probe

_lock = threading.Lock()
_cache = {}


def ollama_model():
    return os.getenv('CBB_OLLAMA_MODEL', 'qwen2.5:0.5b')


def ollama_status():
    from .assistant import ollama_url
    model = ollama_model()
    try:
        with httpx.Client(timeout=3, trust_env=False) as client:
            response = client.get(ollama_url() + '/api/tags')
            response.raise_for_status()
            names = [m['name'] for m in response.json().get('models', [])]
            present = model in names
            if present:
                show = client.post(ollama_url() + '/api/show', json={'model': model})
                show.raise_for_status()
                info = show.json()
                if info.get('remote_host') or info.get('remote_model'):
                    return {'state': 'REMOTE_MODEL_REJECTED', 'model': model}
            return {'state': 'AVAILABLE' if present else 'MODEL_MISSING', 'model': model, 'models': names, 'version': 'Local API reachable; inference is checked when analysis runs'}
    except Exception:
        return {'state': 'UNAVAILABLE', 'model': model, 'detail': 'Local Ollama API is not reachable or returned invalid metadata'}


def host_status():
    with _lock:
        if time.monotonic() - _cache.get('at', -1000) < 30:
            return _cache['value']
        firewall = {'state': 'NOT_APPLICABLE', 'profiles': []}
        suricata = tool_probe('suricata', '-V')
        if os.name == 'nt':
            state_file=Path(__file__).resolve().parent.parent/'sensor-data/wsl-setup.json'
            if state_file.is_file() and state_file.stat().st_size<32768:
                try:suricata['wsl_setup']=json.loads(state_file.read_text(encoding='utf-8-sig'))
                except (ValueError,OSError):pass
            try:
                code, output = bounded_process(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', 'Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Select-Object Name,Enabled,LogAllowed,LogBlocked,LogFileName | ConvertTo-Json -Compress'], 10)
                if code:
                    raise ValueError('Firewall profile query failed')
                profiles = json.loads(output)
                if isinstance(profiles, dict):profiles = [profiles]
                firewall = {'state': 'ENABLED' if profiles and all(p['Enabled'] == 1 for p in profiles) else 'PARTLY_DISABLED', 'profiles': profiles, 'logging_enabled': bool(profiles) and all(p['LogBlocked'] == 1 and p['LogAllowed'] == 1 for p in profiles)}
            except (OSError, ValueError, subprocess.TimeoutExpired):
                firewall = {'state': 'UNAVAILABLE', 'profiles': [], 'detail': 'Cannot query Windows Firewall from this server account'}
            # Do not start WSL just to probe the web dashboard. The collector
            # heartbeat reports whether the actual WSL capture process is alive.
            suricata['detail'] = 'Native Windows binary probe. Check collector EVE status for actual adapter activity.'
        value = {'checked_at': now(), 'firewall': firewall, 'ollama': ollama_status(), 'suricata': suricata}
        _cache.update(at=time.monotonic(), value=value)
        return value
