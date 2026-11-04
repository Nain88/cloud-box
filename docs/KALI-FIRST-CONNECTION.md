# Kali VM ko apne Windows Cyber Black Box se connect karo

Kali pehle se VMware mein hai to isi VM ko sensor banao. Pi ke liye doosri VM install karne ki zaroorat nahi. Ye software-role test hai. Asli Raspberry Pi ke ARM processor, GPIO aur hardware performance alag test honge.

**1. VMware.** Kali VM ki Settings → Network Adapter → NAT aur Connected select karo. Kali boot karo.

**2. Kali terminal.** Neeche ke commands ek ek kar ke chalao:

```bash
sudo apt update
sudo apt install -y openssh-server python3 python3-venv unzip curl
sudo ssh-keygen -A
sudo systemctl start ssh
systemctl is-active ssh
whoami
ip -br -4 addr
python3 --version
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

SSH ka result active hona chahiye. Username, NAT adapter ka IPv4 (127.0.0.1 nahi), aur SHA256 fingerprint note karo. Python 3.12 ya newer chahiye.

**3. Windows PowerShell.** Windows dashboard chalta rehna chahiye. Neeche Kali ka username aur IP do:

```powershell
Set-Location -LiteralPath 'C:\Users\PC Tecnologies\Documents\ChatGPT\cloud box'
$vmUser = Read-Host 'Kali username'
$vmIP = Read-Host 'Kali NAT IPv4'
$vm = "${vmUser}@${vmIP}"
Test-NetConnection $vmIP -Port 22
(Invoke-RestMethod http://127.0.0.1:8765/api/v1/status).public_key
scp.exe -o HostKeyAlgorithms=ssh-ed25519 .\release\Cyber-Black-Box-Complete-Project.zip "${vm}:cbb.zip"
ssh.exe -o HostKeyAlgorithms=ssh-ed25519 -N -o ExitOnForwardFailure=yes -R 127.0.0.1:18765:127.0.0.1:8765 $vm
```

TcpTestSucceeded True ho. Pehli dafa fingerprint Step 2 se match karo. Password Kali ka hai. Windows ki public key sambhal lo. SSH command ke baad PowerShell khaali nazar aayega. Isay khula rakho.

**4. Kali terminal.** Ye test Windows ki public key ke saath wahi dashboard status lautaye:

```bash
curl -fsS http://127.0.0.1:18765/api/v1/status
```

Connection refused aaye to pehle Windows dashboard aur SSH window check karo. Sahi status ke baad:

```bash
bash
mkdir -p ~/cbb-lab ~/cbb-watch
unzip -n ~/cbb.zip -d ~/cbb-lab
cd ~/cbb-lab/Cyber-Black-Box
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -c requirements.lock httpx psutil cryptography rfc8785 watchdog
```

**5. Windows dashboard.** Admin login → Collectors → Enroll collector → name Kali VM → Linux → Create enrollment token. Token single-use hai, 10 minutes mein expire hota hai.

**6. Kali terminal.** Step 4 ke Bash aur active venv mein:

```bash
read -rsp 'Enrollment token: ' CBB_ENROLLMENT_TOKEN; echo
export CBB_ENROLLMENT_TOKEN
read -rp 'Windows ki trusted public key: ' key
python -m cbb.agent --config ~/cbb-agent/agent.json enroll --server http://127.0.0.1:18765 --server-key "$key" --name 'Kali VM' --enable-events --allow-path "$HOME/cbb-watch"
unset CBB_ENROLLMENT_TOKEN
echo "$HOME/cbb-watch"
python -m cbb.agent --config ~/cbb-agent/agent.json run
```

**7. Pehla real test.** Windows dashboard → Collectors → Kali VM → Configure. Allowed file paths mein echo ka exact path daalo. Windows channels khaali rakho aur save karo. Recent heartbeat ka intezar karo. Doosra Kali terminal kholo:

```bash
echo 'pehla record' > ~/cbb-watch/demo.txt
```

Windows Evidence explorer mein investigator login se source fim dekho. Pehla record aane par:

```bash
echo 'doosra record' >> ~/cbb-watch/demo.txt
```

Doosre record ka hash badalna chahiye. Dono records ek chhotay case mein add karo aur Reports & exports se report banao. Admin sirf assigned cases ke records dekhta hai.

**Agli baar:** Windows dashboard, Kali SSH service, Windows tunnel aur Kali collector run karo. Enrollment repeat mat karo. Agar baad mein physical Pi use karo to usay alag Linux collector ki tarah naya token do.
