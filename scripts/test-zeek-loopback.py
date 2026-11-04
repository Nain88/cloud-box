"""Capture one local HTTP exchange and replay only that capture with the lab Zeek build."""
import ctypes as ct
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid


class Filter(ct.Structure):
    _fields_ = [('length', ct.c_uint), ('instructions', ct.c_void_p)]


def capture_local(path):
    directory = Path(os.environ['SystemRoot']) / 'System32/Npcap'
    with os.add_dll_directory(str(directory)):
        lib = ct.CDLL(str(directory / 'wpcap.dll'))
    ptr = ct.c_void_p
    signatures = {
        'pcap_open_live': (ptr, [ct.c_char_p, ct.c_int, ct.c_int, ct.c_int, ct.c_char_p]),
        'pcap_close': (None, [ptr]), 'pcap_geterr': (ct.c_char_p,[ptr]),
        'pcap_compile': (ct.c_int,[ptr,ct.POINTER(Filter),ct.c_char_p,ct.c_int,ct.c_uint]),
        'pcap_setfilter': (ct.c_int,[ptr,ct.POINTER(Filter)]), 'pcap_freecode': (None,[ct.POINTER(Filter)]),
        'pcap_setnonblock': (ct.c_int,[ptr,ct.c_int,ct.c_char_p]),
        'pcap_dump_open': (ptr,[ptr,ct.c_char_p]), 'pcap_dump_close': (None,[ptr]),
        'pcap_next_ex': (ct.c_int,[ptr,ct.POINTER(ptr),ct.POINTER(ptr)]),
        'pcap_dump': (None,[ptr,ptr,ptr]),
    }
    for name,(result,args) in signatures.items():
        func = getattr(lib,name);func.restype=result;func.argtypes=args
    error = ct.create_string_buffer(256)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(3)
        port=listener.getsockname()[1]
        handle=lib.pcap_open_live(br'\Device\NPF_Loopback', 65535, 0, 50, error)
        if not handle:raise RuntimeError(error.value.decode(errors='replace'))
        dump=None
        try:
            program=Filter()
            pattern=f'ip and host 127.0.0.1 and tcp port {port}'.encode()
            if lib.pcap_compile(handle,ct.byref(program),pattern,1,0xffffffff):raise RuntimeError('Npcap filter compile failed')
            try:
                if lib.pcap_setfilter(handle,ct.byref(program)):raise RuntimeError('Npcap filter rejected')
            finally:lib.pcap_freecode(ct.byref(program))
            if lib.pcap_setnonblock(handle,1,error):raise RuntimeError(error.value.decode(errors='replace'))
            dump=lib.pcap_dump_open(handle,os.fsencode(path))
            if not dump:raise RuntimeError(lib.pcap_geterr(handle).decode(errors='replace'))
            with socket.create_connection(('127.0.0.1',port),timeout=3) as client:
                connection,_=listener.accept()
                with connection:
                    connection.settimeout(3)
                    client.sendall(b'GET /cbb-zeek-test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                    if not connection.recv(1024).startswith(b'GET /cbb-zeek-test '):raise RuntimeError('Unexpected request')
                    connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
                if not client.recv(1024).startswith(b'HTTP/1.1 200 OK'):raise RuntimeError('Local HTTP exchange failed')
            end=time.monotonic()+2;count=0
            while time.monotonic()<end and count<128:
                hdr,packet=ptr(),ptr();rc=lib.pcap_next_ex(handle,ct.byref(hdr),ct.byref(packet))
                if rc==0:time.sleep(.02);continue
                if rc<0:raise RuntimeError('Npcap read failed')
                lib.pcap_dump(dump,hdr,packet);count+=1
            if not count:raise RuntimeError('Npcap captured zero test packets')
            return port,count
        finally:
            if dump:lib.pcap_dump_close(dump)
            lib.pcap_close(handle)


def main():
    root=Path(__file__).resolve().parents[1]
    install=Path(os.environ['LOCALAPPDATA'])/'Programs/CyberBlackBox/zeek-v7.0.0-brim1/zeek'
    run=root/'work'/('zeek-test-'+uuid.uuid4().hex);run.mkdir(parents=True)
    pcap=run/'local-http.pcap';port,count=capture_local(pcap)
    env=dict(os.environ,ZEEKPATH=';'.join((install/p).as_posix() for p in ('share/zeek','share/zeek/policy','share/zeek/site')))
    exe=str(install/'bin/zeek.exe')
    subprocess.run([exe,'-C','-r',pcap.name,'LogAscii::use_json=T'],env=env,cwd=run,check=True,timeout=60)
    matches=[]
    for raw in (run/'conn.log').read_bytes().splitlines(keepends=True):
        obs=json.loads(raw)
        if obs.get('id.orig_h')=='127.0.0.1' and obs.get('id.resp_h')=='127.0.0.1' and obs.get('id.resp_p')==port:
            matches.append((raw,obs))
    if len(matches)!=1:raise RuntimeError('Expected exactly one local Zeek connection record')
    raw,obs=matches[0];target=root/'sensor-data/zeek/conn.log';target.parent.mkdir(parents=True,exist_ok=True)
    with target.open('ab') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    result={'pcap':str(pcap),'pcap_sha256':hashlib.sha256(pcap.read_bytes()).hexdigest(),'packets':count,'uid':obs['uid'],'port':port,'raw_sha256':hashlib.sha256(raw).hexdigest(),'collector_input':str(target),'mode':'controlled loopback capture, offline Zeek replay'}
    (run/'result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))


if __name__=='__main__':main()
