"""Bounded access to explicitly installed vendor tools; no command shell."""
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from .service import DomainError

def bounded_process(command,timeout):
    # Vendor clients can launch a persistent service that inherits stdout.
    # A pipe-based communicate() can then wait forever even after the client
    # exits. A temporary file lets us wait only for this specific child.
    with tempfile.TemporaryFile() as output:
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=output,stderr=output,shell=False,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        try:process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill();process.wait(timeout=5);raise
        output.seek(0)
        return process.returncode,output.read(4000).decode("utf-8",errors="replace").strip()

def mega_command(verb, *args, timeout=600):
    if verb not in {"version","whoami","mkdir","put","get","ls"}:raise ValueError("Unsupported MEGA operation")
    configured=os.getenv("CBB_MEGACMD_DIR","")
    if os.name=="nt":
        root=Path(configured or Path(os.getenv("LOCALAPPDATA",""))/"MEGAcmd")
        client=root/"MegaClient.exe"
        if not client.is_file():raise DomainError("MEGA_NOT_INSTALLED","Install official MEGAcmd and sign in locally; see Integrations setup",422)
        command=[str(client),verb,*map(str,args)]
    else:
        executable=str(Path(configured)/("mega-"+verb)) if configured else shutil.which("mega-"+verb)
        if not executable or not Path(executable).is_file():raise DomainError("MEGA_NOT_INSTALLED","Official MEGAcmd is not installed",422)
        command=[executable,*map(str,args)]
    try:
        returncode,output=bounded_process(command,timeout)
    except subprocess.TimeoutExpired as ex:raise DomainError("MEGA_TIMEOUT","MEGA operation timed out; remote transfer may still be pending; retry verifies before upload",503) from ex
    except OSError as ex:raise DomainError("MEGA_UNAVAILABLE","MEGAcmd could not start. Check executable permissions and the local service session",503) from ex
    if returncode:raise DomainError("MEGA_OPERATION_FAILED",f"MEGA {verb} failed (code {returncode}). Check local login, storage/transfer quota and connection in MEGAcmd.",503)
    return output

def tool_probe(name, argument="--version"):
    candidate=os.getenv("CBB_"+name.upper()+"_EXECUTABLE") or shutil.which(name)
    if not candidate and name=='zeek' and os.name=='nt':
        candidate=str(Path(os.environ['LOCALAPPDATA'])/'Programs/CyberBlackBox/zeek-v7.0.0-brim1/zeek/bin/zeek.exe')
    if not candidate and name=='suricata' and os.name=='nt':
        candidate=str(Path(os.environ['ProgramFiles'])/'Suricata/suricata.exe')
    try:
        if not candidate or not Path(candidate).is_file():return {"state":"NOT_INSTALLED","version":None}
        code,output=bounded_process([candidate,argument],8)
        return {"state":"AVAILABLE" if code==0 else "ERROR","version":output[:300],"path":candidate}
    except (OSError,subprocess.TimeoutExpired):return {"state":"ERROR","version":None}
