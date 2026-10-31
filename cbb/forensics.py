"""Optional bounded Volatility 3 analysis of an already acquired memory image."""
import argparse
import json
import subprocess
from pathlib import Path
from .crypto import file_sha,atomic_write,canon,now

PLUGINS=("windows.info","windows.pslist","windows.pstree","windows.netscan","linux.banners","linux.pslist")

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path);p.add_argument("--tool",required=True,type=Path,help="Absolute path to installed Volatility 3 executable")
    p.add_argument("--tool-sha256",required=True);p.add_argument("--image-sha256",required=True)
    p.add_argument("--plugin",choices=PLUGINS,default="windows.info");p.add_argument("--output",required=True,type=Path)
    p.add_argument("--timeout",type=int,default=300)
    a=p.parse_args()
    if not a.tool.is_absolute() or not a.tool.is_file():p.error("Provide an existing absolute tool path")
    if file_sha(a.tool)!=a.tool_sha256 or file_sha(a.image)!=a.image_sha256:p.error("Input image or tool hash mismatch")
    if a.output.exists():p.error("Output directory must be new")
    a.output.mkdir(parents=True)
    command=[str(a.tool),"--offline","-f",str(a.image.resolve()),"-r","json",a.plugin]
    status="FAILED";code=None
    with (a.output/"result.json").open("wb") as out,(a.output/"stderr.txt").open("wb") as err:
        process=subprocess.Popen(command,stdout=out,stderr=err,shell=False)
        import time
        deadline=time.monotonic()+min(1800,max(10,a.timeout))
        while process.poll() is None:
            if time.monotonic()>deadline or out.tell()>128*1024**2 or err.tell()>8*1024**2:
                process.kill();process.wait();status="BUDGET_EXCEEDED";break
            time.sleep(.2)
        else:
            code=process.returncode;status="COMPLETE" if code==0 else "FAILED"
    atomic_write(a.output/"manifest.json",canon({"status":status,"exit_code":code,"tool_sha256":a.tool_sha256,"image_sha256":a.image_sha256,"plugin":a.plugin,"result_sha256":file_sha(a.output/"result.json"),"created_at":now()}))
    print(json.dumps({"status":status,"output":str(a.output.resolve())}))
    return 0 if status=="COMPLETE" else 2

if __name__=="__main__":raise SystemExit(main())
