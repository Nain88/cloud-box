"""Run genuine Suricata with bounded duration/disk, writing status beside EVE.
Standalone standard-library script: callable with Ubuntu's system Python.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--interface',required=True)
    p.add_argument('--config',required=True,type=Path)
    p.add_argument('--rules',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--seconds',type=int,default=900)
    p.add_argument('--max-mib',type=int,default=256)
    args=p.parse_args()
    if not 30<=args.seconds<=86400 or not 16<=args.max_mib<=4096:p.error('Duration 30–86400 seconds and budget 16–4096 MiB required')
    if not Path('/sys/class/net',args.interface).is_dir():p.error('Select an existing authorized interface using ip -brief link')
    args.output.mkdir(parents=True,exist_ok=True)
    lock=args.output/'sensor.lock'
    try:lockfd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    except FileExistsError:p.error('Sensor lock exists. Check the previous PID before removing a stale lock.')
    os.write(lockfd,str(os.getpid()).encode());os.close(lockfd)
    process=None;started=time.monotonic();reason='STARTING'
    info={'schema':'cbb.sensor-status/1','scope':'Only traffic visible on this Linux interface; WSL does not imply full Windows capture','interface':args.interface,'state':'STARTING'}
    def save():
        info.update(updated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),elapsed_seconds=round(time.monotonic()-started),reason=reason)
        tmp=args.output/'sensor-status.tmp';tmp.write_text(json.dumps(info,indent=2));os.replace(tmp,args.output/'sensor-status.json')
    try:
        version=subprocess.run(['suricata','-V'],capture_output=True,text=True,check=True,timeout=15)
        info.update(version=version.stdout.strip(),config_sha256=hashlib.sha256(args.config.read_bytes()).hexdigest(),rules_sha256=hashlib.sha256(args.rules.read_bytes()).hexdigest())
        feed=Path('/var/lib/suricata/rules/suricata.rules')
        if not feed.is_file() or not feed.stat().st_size:raise RuntimeError('ET Open rules missing; rerun setup or suricata-update')
        info.update(feed_sha256=hashlib.sha256(feed.read_bytes()).hexdigest(),feed_modified_at=datetime.datetime.fromtimestamp(feed.stat().st_mtime,datetime.timezone.utc).isoformat())
        command=['suricata','-c',str(args.config),'-s',str(args.rules),'-l',str(args.output)]
        subprocess.run(command+['-T'],check=True,timeout=60)
        with (args.output/'console.log').open('ab') as log:
            process=subprocess.Popen(command+['-i',args.interface,'--runmode','single'],stdout=log,stderr=subprocess.STDOUT)
            info.update(pid=process.pid,state='RUNNING');reason='CAPTURING';save()
            while process.poll() is None:
                size=sum(f.stat().st_size for f in args.output.iterdir() if f.is_file())
                info['output_bytes']=size
                if size>=args.max_mib*1024**2:reason='DISK_BUDGET_REACHED';break
                if time.monotonic()-started>=args.seconds:reason='DURATION_REACHED';break
                save();time.sleep(2)
            else:reason='PROCESS_EXITED'
    except KeyboardInterrupt:reason='OPERATOR_STOP'
    except Exception as ex:
        info['error']=type(ex).__name__+': '+str(ex)[:500];reason='ERROR'
        raise
    finally:
        if process and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:process.wait(timeout=15)
            except subprocess.TimeoutExpired:process.kill();process.wait();reason='FORCED_STOP'
        info.update(state='STOPPED',exit_code=process.returncode if process else None);save();lock.unlink(missing_ok=True)
    if process and process.returncode not in (0,None):raise SystemExit(process.returncode)

if __name__=='__main__':main()
