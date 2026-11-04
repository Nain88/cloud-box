"""Run an operator-selected Windows/Npcap adapter with the vendor IDS engine."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
from datetime import datetime, timezone


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--device', required=True)
    p.add_argument('--label', required=True)
    p.add_argument('--seconds', type=int, default=900)
    p.add_argument('--max-mib', type=int, default=256)
    args = p.parse_args()
    if not 30 <= args.seconds <= 86400 or not 16 <= args.max_mib <= 4096:
        p.error('Select 30–86400 seconds and 16–4096 MiB')
    root = Path(__file__).resolve().parents[2]
    output = root / 'sensor-data'
    output.mkdir(exist_ok=True)
    install = Path(os.environ['ProgramFiles']) / 'Suricata'
    exe = install / 'suricata.exe'
    config = install / 'suricata.yaml'
    lock = output / 'sensor.lock'
    with lock.open('x') as f:
        f.write(str(os.getpid()))
    info = {'platform':'Windows/Npcap', 'scope':'Traffic on the selected adapter only', 'interface':args.label, 'state':'STARTING','started_at':timestamp()}
    manifest = output / 'sensor-status.json'
    def save():
        info['updated_at'] = timestamp()
        tmp = manifest.with_suffix('.tmp')
        tmp.write_text(json.dumps(info,indent=2),encoding='utf-8')
        os.replace(tmp,manifest)
    child = None
    try:
        save()
        version = subprocess.check_output([str(exe),'-V'], stderr=subprocess.STDOUT,timeout=15).decode(errors='replace').strip()
        families = ('app-layer','decoder','dns','http','http2','smb','ssh','stream','tls')
        vendor_rules = [install/'rules'/f'{family}-events.rules' for family in families]
        rules = output / 'windows-active.rules'
        rules.write_bytes(b'\n'.join(path.read_bytes() for path in [*vendor_rules,root/'rules/cbb-demo.rules',root/'rules/cbb-web.rules']))
        info.update(version=version,rules_sha256=hashlib.sha256(rules.read_bytes()).hexdigest(),config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),rule_sources=[path.name for path in vendor_rules]+['cbb-demo.rules','cbb-web.rules'])
        # Windows captures outbound packets before the NIC fills checksums.
        # Disable checksum validation for this capture-only laptop profile.
        info['checksum_validation']='disabled for NIC checksum offload'
        threshold=output/'windows-offload-threshold.config'
        if not threshold.exists():
            threshold.write_text(''.join(f'threshold gen_id 1, sig_id {sid}, type limit, track by_src, count 1, seconds 60\n' for sid in range(2200073,2200080)),encoding='ascii')
        info['threshold_sha256']=hashlib.sha256(threshold.read_bytes()).hexdigest()
        command=[str(exe),'-c',str(config),'-S',str(rules),'-l',str(output),'--set','threshold-file='+str(threshold),'-k','none','--runmode','single']
        with (output/'windows-console.log').open('ab') as console:
            subprocess.run(command+['-T'],cwd=install,stdout=console,stderr=subprocess.STDOUT,check=True,timeout=120)
            child=subprocess.Popen(command+['-i',args.device],cwd=install,stdout=console,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            started=time.monotonic();info.update(pid=child.pid,state='RUNNING')
            while child.poll() is None:
                size=sum(path.stat().st_size for path in output.iterdir() if path.is_file())
                info.update(output_bytes=size);save()
                if size>=args.max_mib*1024**2:
                    info['reason']='DISK_BUDGET_REACHED';break
                if time.monotonic()-started>=args.seconds:
                    info['reason']='DURATION_REACHED';break
                time.sleep(2)
            if child.poll() is not None and child.returncode:
                raise RuntimeError(f'Suricata exited {child.returncode}. Inspect sensor-data/windows-console.log')
    except KeyboardInterrupt:
        info['reason']='OPERATOR_STOP'
    except Exception as exc:
        info['reason']='ERROR';info['error']=str(exc)[:500];raise
    finally:
        try:
            if child and child.poll() is None:
                try:child.send_signal(signal.CTRL_BREAK_EVENT);child.wait(timeout=12)
                except (OSError, subprocess.TimeoutExpired):child.terminate();child.wait(timeout=8);info['stop_method']='TERMINATED'
        finally:
            info.update(state='STOPPED',exit_code=child.returncode if child else None);save();lock.unlink(missing_ok=True)


if __name__=='__main__':main()
