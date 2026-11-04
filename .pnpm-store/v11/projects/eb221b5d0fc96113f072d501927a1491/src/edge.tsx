import React,{useState} from 'react';
import {CircuitBoard,Terminal,ArrowRight,Network,Fingerprint} from 'lucide-react';
import {Panel,CopyButton,useApp} from './ui';

export function SignalBanner(){
 const {go}=useApp();
 return <section className="signal-banner"><div><div className="signal-label">CBB / INVESTIGATION CONSOLE</div><h2>Evidence operations</h2><p>Follow an observation from sensor to signed report.</p><button onClick={()=>go('live')}>Open live monitor <ArrowRight size={15}/></button></div><div className="signal-route" aria-hidden="true"><Network/><i/><Fingerprint/><i/><CircuitBoard/></div></section>;
}

function Command({text}:{text:string}){return <div className="edge-command"><pre>{text}</pre><CopyButton value={text}/></div>}
export function EdgeSetup(){
 const [target,setTarget]=useState('Kali VM');
 return <Panel title="Connect a Linux sensor" subtitle="Enroll a Kali virtual machine or prepare a physical Raspberry Pi for testing.">
 <details className="edge-setup"><summary><Terminal size={17}/> Open connection guide</summary>
 <label>Endpoint <select aria-label="Endpoint" value={target} onChange={e=>setTarget(e.target.value)}><option>Kali VM</option><option>Raspberry Pi</option></select></label>
 <ol><li><strong>Prepare {target}</strong><p>{target==='Kali VM'?'Use VMware NAT and confirm that Windows can reach the VM.':'Use 64-bit Raspberry Pi OS and confirm Windows can reach the Pi on your private network. ARM hardware validation is pending.'} Check for Python 3.12 or newer. On the endpoint run:</p>
 <Command text={'sudo apt update\nsudo apt install -y openssh-server python3 python3-venv unzip curl\nsudo ssh-keygen -A\nsudo systemctl start ssh\nwhoami; hostname -I; python3 --version\nssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub'}/></li>
 <li><strong>Connect Windows to the endpoint</strong><p>Keep the Windows dashboard running. In PowerShell, from the project folder, enter the endpoint username and IP. Compare the SSH fingerprint with the endpoint before accepting. Keep the tunnel window open.</p>
 <Command text={'$userName = Read-Host "Endpoint username"\n$address = Read-Host "Endpoint IPv4"\n$targetHost = "${userName}@${address}"\n(Invoke-RestMethod http://127.0.0.1:8765/api/v1/status).public_key\nscp.exe -o HostKeyAlgorithms=ssh-ed25519 .\\release\\Cyber-Black-Box-Complete-Project.zip "${targetHost}:cbb.zip"\nssh.exe -N -o ExitOnForwardFailure=yes -R 127.0.0.1:18765:127.0.0.1:8765 $targetHost'}/></li>
 <li><strong>Install the collector</strong><p>On the endpoint, use Bash. Confirm the status request returns the same public key as Windows before continuing.</p>
 <Command text={'bash\ncurl -fsS http://127.0.0.1:18765/api/v1/status\nmkdir -p ~/cbb-lab ~/cbb-watch\nunzip -n ~/cbb.zip -d ~/cbb-lab\ncd ~/cbb-lab/Cyber-Black-Box\npython3 -m venv .venv\nsource .venv/bin/activate\npython -m pip install -c requirements.lock httpx psutil cryptography rfc8785 watchdog'}/></li>
 <li><strong>Enroll and verify</strong><p>Use Enroll collector above, choose Linux, then paste its single-use token at the hidden prompt. Use the public key from Windows. Run enrollment once per endpoint.</p>
 <Command text={'read -rsp "Enrollment token: " CBB_ENROLLMENT_TOKEN; echo\nexport CBB_ENROLLMENT_TOKEN\nread -rp "Trusted Windows public key: " serverKey\npython -m cbb.agent --config ~/cbb-agent/agent.json enroll --server http://127.0.0.1:18765 --server-key "$serverKey" --name "'+target+'" --enable-events --allow-path "$HOME/cbb-watch"\nunset CBB_ENROLLMENT_TOKEN\npython -m cbb.agent --config ~/cbb-agent/agent.json run'}/>
 <p>Check for a recent heartbeat in the collector table. In Configure, add the full endpoint path to cbb-watch. Create a file there and inspect the resulting FIM evidence using an investigator account.</p></li></ol></details></Panel>;
}
