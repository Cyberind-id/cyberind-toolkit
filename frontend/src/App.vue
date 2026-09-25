<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { invoke } from "./lib/api";
import PortScan from "./components/modules/PortScan.vue";
import SubEnum from "./components/modules/SubEnum.vue";
import HttpProbe from "./components/modules/HttpProbe.vue";
import Takeover from "./components/modules/Takeover.vue";
import Sqli from "./components/modules/Sqli.vue";
import Xss from "./components/modules/Xss.vue";
import Jwt from "./components/modules/Jwt.vue";
import Xploiter from "./components/modules/Xploiter.vue";
import AutoPwn from "./components/modules/AutoPwn.vue";
import LanMap from "./components/modules/LanMap.vue";
import Repeater from "./components/modules/Repeater.vue";
import DirFuzz from "./components/modules/DirFuzz.vue";
import PayloadGen from "./components/modules/PayloadGen.vue";
import AdminFinder from "./components/modules/AdminFinder.vue";
import FormBrute from "./components/modules/FormBrute.vue";
import DnsTools from "./components/modules/DnsTools.vue";
import SslScan from "./components/modules/SslScan.vue";
import Banner from "./components/modules/Banner.vue";
import Encoder from "./components/modules/Encoder.vue";
import HashTools from "./components/modules/HashTools.vue";
import DomainGrabber from "./components/modules/DomainGrabber.vue";
import SplashScreen from "./components/SplashScreen.vue";

type ToolId = "ports"|"subs"|"httpx"|"takeguard"|"sqltrace"|"xenxss"|"tokenscope"|"vulnforge"|"autopwn"|"lanmap"|"reqlab"|"dirfuzz"|"payloadgen"|"adminfinder"|"formbrute"|"dnscope"|"ssl"|"banner"|"codeshift"|"hash"|"domgrab";
type Cat = "recon"|"exploit"|"utility"|"network"|"manual";
interface Tool { id:ToolId; code:string; name:string; tagline:string; desc:string; cat:Cat; severity:string }

const tools:Tool[]=[
{id:"ports",code:"01",name:"PortRay",tagline:"tcp connect",desc:"Async port discovery and service hints.",cat:"recon",severity:"info"},
{id:"subs",code:"02",name:"SubFindr",tagline:"passive + brute",desc:"Certificate sources and wordlist enumeration.",cat:"recon",severity:"info"},
{id:"httpx",code:"03",name:"WebProbeX",tagline:"status + tech",desc:"Live host probing and technology hints.",cat:"recon",severity:"info"},
{id:"takeguard",code:"04",name:"TakeGuard",tagline:"CNAME audit",desc:"Detect common dangling service configurations.",cat:"exploit",severity:"high"},
{id:"sqltrace",code:"05",name:"SQLTrace",tagline:"error/bool/time",desc:"SQL injection testing for authorized targets.",cat:"exploit",severity:"critical"},
{id:"xenxss",code:"06",name:"XenXSS",tagline:"context-aware",desc:"Reflection and context checks for XSS.",cat:"exploit",severity:"high"},
{id:"tokenscope",code:"07",name:"TokenScope",tagline:"jwt inspector",desc:"JWT decoding and security inspection.",cat:"exploit",severity:"critical"},
{id:"vulnforge",code:"08",name:"VulnForge",tagline:"template engine",desc:"Template-driven vulnerability testing.",cat:"exploit",severity:"critical"},
{id:"autopwn",code:"09",name:"ReconFlow",tagline:"full chain",desc:"Automated reconnaissance workflow.",cat:"exploit",severity:"critical"},
{id:"lanmap",code:"10",name:"NetGrid",tagline:"local network",desc:"Network discovery and device mapping.",cat:"network",severity:"info"},
{id:"reqlab",code:"11",name:"ReqLab",tagline:"request lab",desc:"Craft, send, inspect and replay HTTP.",cat:"manual",severity:"info"},
{id:"dirfuzz",code:"12",name:"DirTrace",tagline:"content discovery",desc:"Directory and endpoint discovery.",cat:"exploit",severity:"medium"},
{id:"payloadgen",code:"13",name:"PayloadForge",tagline:"payload builder",desc:"Payload generation utilities for lab use.",cat:"utility",severity:"info"},
{id:"adminfinder",code:"14",name:"PanelSeek",tagline:"panel discovery",desc:"Discover common administration paths.",cat:"exploit",severity:"medium"},
{id:"formbrute",code:"15",name:"AuthProbe",tagline:"login testing",desc:"Credential testing for authorized forms.",cat:"exploit",severity:"high"},
{id:"dnscope",code:"16",name:"DNScope",tagline:"record lookup",desc:"DNS records, DNSSEC and diagnostics.",cat:"network",severity:"info"},
{id:"ssl",code:"17",name:"CertScope",tagline:"tls inspector",desc:"Certificate chain and TLS inspection.",cat:"network",severity:"info"},
{id:"banner",code:"18",name:"ServiceEye",tagline:"service fingerprint",desc:"TCP service and banner inspection.",cat:"network",severity:"info"},
{id:"codeshift",code:"19",name:"CodeShift",tagline:"chain transforms",desc:"Encoding and decoding utility pipelines.",cat:"utility",severity:"info"},
{id:"hash",code:"20",name:"HashLens",tagline:"id + calc",desc:"Hash identification and calculation.",cat:"utility",severity:"info"},
{id:"domgrab",code:"21",name:"DomainTrace",tagline:"bulk harvest",desc:"Domain collection for authorized research.",cat:"recon",severity:"info"}];

const groups:{id:Cat;label:string;desc:string;mark:string}[]=[
{id:"recon",label:"Reconnaissance",desc:"passive + active discovery",mark:"◉"},
{id:"exploit",label:"Security Testing",desc:"vulnerability assessment",mark:"⌁"},
{id:"network",label:"Network",desc:"network & protocol diagnostics",mark:"≋"},
{id:"manual",label:"Manual",desc:"request analysis workspace",mark:"✎"},
{id:"utility",label:"Utilities",desc:"helpers & transformations",mark:"⚙"}];

const active=ref<ToolId|null>(null), banner=ref(""), clock=ref(""), showSplash=ref(true);
const activeTool=computed(()=>tools.find(t=>t.id===active.value)??null);
const grouped=computed(()=>groups.map(g=>({...g,tools:tools.filter(t=>t.cat===g.id)})).filter(g=>g.tools.length));
function open(id:ToolId){active.value=id} function back(){active.value=null}
function tick(){clock.value=new Date().toTimeString().slice(0,8)}
onMounted(async()=>{try{banner.value=await invoke<string>("banner")}catch{banner.value="CYBERIND TOOLKIT"} tick();setInterval(tick,1000)})
</script>

<template>
<SplashScreen v-if="showSplash" @done="showSplash=false"/>
<div v-show="!showSplash" class="site">
  <div class="progress"></div>
  <header class="header">
    <nav class="nav">
      <button class="brand" @click="back">
        <img src="https://www.cyberind.my.id/assets/images/logoo.png" alt="Cyberind.id">
        <span>cyberind<span class="accent">id</span></span>
      </button>
      <div class="navlinks">
        <button :class="{on:!activeTool}" @click="back">Tools</button>
        <a href="https://cyberind.my.id" target="_blank">Cyberind.id</a>
        <span class="live"><i></i> SYSTEM ONLINE</span>
      </div>
      <div class="navmeta"><span>v0.1.0</span><span>{{clock}}</span></div>
    </nav>
    <div class="crumb"><span>cyberind</span><b>/</b><span>{{activeTool?.name||"toolkit"}}</span><i>_</i></div>
  </header>

  <main>
    <section v-if="!activeTool" class="home">
      <div class="hero reveal">
        <div>
          <div class="eyebrow"><i></i> KOMUNITAS INDEPENDEN SEJAK 2018</div>
          <h1>CYBERIND <span>TOOLKIT</span></h1>
          <p>Security tools untuk reconnaissance, analisis, diagnostik, dan pengujian keamanan dalam satu workspace.</p>
          <div class="hero-actions">
            <button class="primary shimmer" @click="open('ports')">Jelajahi Tools <b>→</b></button>
            <a class="secondary" href="https://cyberind.my.id" target="_blank">cyberind.my.id ↗</a>
          </div>
        </div>
        <div class="terminal terminal-glass">
          <div class="termbar"><span></span><span></span><span></span><b>CYBERIND SYSTEM</b></div>
          <div class="termbody">
            <div>$ ./cyberind --launch</div><div class="ok">[OK] CONNECTED</div><div class="ok">[OK] SECURE</div><div class="ok">[OK] LOADED</div><div class="white">ACCESS GRANTED</div><div class="muted">> cyberind.my.id</div><em></em>
          </div>
        </div>
      </div>

      <div class="intro glass-card reveal">
        <div><small>01 / TOOLKIT</small><h2>Explore. Learn. Share. Build. Secure.</h2></div>
        <p>Cyberind Toolkit adalah workspace web untuk membantu riset keamanan yang dilakukan secara sah dan bertanggung jawab.</p>
      </div>

      <div class="stats glass-card">
        <strong>{{tools.length}} <small>MODULES</small></strong>
        <span v-for="g in grouped" :key="g.id"><b>{{g.mark}}</b> {{g.tools.length}} {{g.label}}</span>
      </div>

      <div class="groups">
        <section v-for="g in grouped" :key="g.id" class="group reveal">
          <div class="ghead"><span>{{g.mark}}</span><strong>{{g.label}}</strong><small>// {{g.desc}}</small><i>[{{g.tools.length}}]</i><hr/></div>
          <div class="grid">
            <button v-for="t in g.tools" :key="t.id" class="card glass-card glass-touch card-h" @click="open(t.id)">
              <div class="ctop"><span>[{{t.code}}]</span><b>{{g.mark}}</b></div>
              <h3>{{t.name}}</h3><small>{{t.tagline}}</small><p>{{t.desc}}</p>
              <div class="cfoot"><em :class="'s-'+t.severity">{{t.severity}}</em><b>↗</b></div>
            </button>
          </div>
        </section>
      </div>
    </section>

    <section v-else class="toolview">
      <button class="back" @click="back">← Kembali ke Toolkit</button>
      <div class="tooltitle glass-card"><small>CYBERIND / SECURITY TOOLS</small><h2>{{activeTool.name}}</h2><p>{{activeTool.desc}}</p></div>
      <PortScan v-if="active==='ports'"/><SubEnum v-else-if="active==='subs'"/><HttpProbe v-else-if="active==='httpx'"/>
      <Takeover v-else-if="active==='takeguard'"/><Sqli v-else-if="active==='sqltrace'"/><Xss v-else-if="active==='xenxss'"/>
      <Jwt v-else-if="active==='tokenscope'"/><Xploiter v-else-if="active==='vulnforge'"/><AutoPwn v-else-if="active==='autopwn'"/>
      <LanMap v-else-if="active==='lanmap'"/><Repeater v-else-if="active==='reqlab'"/><DirFuzz v-else-if="active==='dirfuzz'"/>
      <PayloadGen v-else-if="active==='payloadgen'"/><AdminFinder v-else-if="active==='adminfinder'"/><FormBrute v-else-if="active==='formbrute'"/>
      <DnsTools v-else-if="active==='dnscope'"/><SslScan v-else-if="active==='ssl'"/><Banner v-else-if="active==='banner'"/>
      <Encoder v-else-if="active==='codeshift'"/><HashTools v-else-if="active==='hash'"/><DomainGrabber v-else-if="active==='domgrab'"/>
    </section>
  </main>

  <footer><span>© {{new Date().getFullYear()}} Indonesian Cyber Team (Cyberind.id). Est. 2018.</span><span>{{banner||"Explore. Learn. Share. Build. Secure."}}</span></footer>
</div>
</template>

<style scoped>
.site{min-height:100%;background:transparent;color:#18181b}
.header{position:sticky;top:0;z-index:40;background:rgba(255,255,255,.78);border-bottom:1px solid rgba(239,68,68,.10)}
.nav{max-width:1152px;margin:auto;height:64px;padding:0 24px;display:flex;align-items:center;justify-content:space-between;gap:20px}
.brand{display:flex;align-items:center;gap:10px;font:700 20px "PT Sans",sans-serif;color:#18181b}
.brand img{width:28px;height:28px;object-fit:contain}.accent,.eyebrow,.live,.ghead>span,.ctop>b{color:#ef4444}
.navlinks{display:flex;align-items:center;gap:28px;font:14px "DM Sans",sans-serif;color:#71717a}.navlinks button,.navlinks a{color:inherit}.navlinks .on{color:#ef4444}.live{font-size:11px;font-weight:600;letter-spacing:.12em}.live i{display:inline-block;width:6px;height:6px;border-radius:50%;background:#ef4444;box-shadow:0 0 8px #ef4444;margin-right:5px}
.navmeta{display:flex;gap:12px;font:11px "DM Sans";color:#a1a1aa}.crumb{max-width:1152px;margin:auto;padding:0 24px 8px;font:11px "DM Sans";color:#71717a}.crumb span:first-child{color:#ef4444}.crumb b{margin:0 5px;color:#d4d4d8}.crumb i{color:#ef4444;font-style:normal;animation:blink 1s infinite}@keyframes blink{50%{opacity:0}}
main{max-width:1152px;margin:auto;padding:34px 24px 70px}.hero{display:grid;grid-template-columns:1.15fr .85fr;gap:32px;align-items:center;padding:48px 0}.eyebrow{font:600 12px "DM Sans";letter-spacing:.14em;margin-bottom:14px}.eyebrow i{display:inline-block;width:7px;height:7px;border-radius:50%;background:#ef4444;margin-right:7px}.hero h1{font:700 clamp(42px,7vw,76px) "PT Sans";letter-spacing:-.045em;line-height:.95;margin:0}.hero h1 span{color:#ef4444}.hero p{font:400 17px/1.7 "DM Sans";color:#71717a;max-width:620px;margin:22px 0}.hero-actions{display:flex;gap:10px;align-items:center}.primary,.secondary{border-radius:12px;padding:12px 17px;font:600 13px "DM Sans";transition:.2s}.primary{background:#ef4444;color:#fff;box-shadow:0 10px 25px rgba(239,68,68,.18)}.primary:hover{transform:translateY(-2px);background:#dc2626}.secondary{border:1px solid rgba(239,68,68,.18);color:#52525b;background:rgba(255,255,255,.5)}.secondary:hover{border-color:#ef4444;color:#ef4444}
.terminal{border-radius:18px;overflow:hidden}.termbar{height:42px;padding:0 15px;display:flex;align-items:center;gap:7px;color:#d4d4d8;font:11px "DM Sans";background:rgba(17,19,24,.9)}.termbar span{width:9px;height:9px;border-radius:50%;background:#ef4444}.termbar span:nth-child(2){background:#f59e0b}.termbar span:nth-child(3){background:#22c55e}.termbar b{margin-left:auto;font-weight:500}.termbody{min-height:245px;padding:25px;font:13px/2 "JetBrains Mono",monospace;color:#d4d4d8;background:rgba(17,19,24,.72)}.termbody .ok{color:#86efac}.termbody .white{color:#fff}.termbody .muted{color:#a1a1aa}.termbody em{display:inline-block;width:8px;height:15px;background:#fff;animation:blink 1s infinite}
.glass-card{background:rgba(240,246,255,.75);border:1px solid rgba(254,202,202,.6);}.dark .glass-card{background:rgba(24,24,27,.75);border-color:rgba(255,255,255,.1)}.terminal-glass{background:rgba(17,19,24,.65)!important;border:1px solid rgba(255,255,255,.12)!important}
.intro{border-radius:20px;padding:25px;display:grid;grid-template-columns:1fr 1fr;gap:30px;align-items:center;margin-bottom:14px}.intro small,.tooltitle small{font:700 10px "DM Sans";letter-spacing:.15em;color:#ef4444}.intro h2{font:700 25px "PT Sans";margin-top:7px}.intro p{font:14px/1.7 "DM Sans";color:#71717a}
.stats{display:flex;align-items:center;gap:18px;flex-wrap:wrap;border-radius:18px;padding:13px 16px;margin-bottom:34px;font:12px "DM Sans";color:#71717a}.stats strong{color:#18181b;font:700 13px "DM Sans";margin-right:4px}.stats strong small{font-size:9px;letter-spacing:.15em}.stats span b{color:#ef4444}
.groups{display:flex;flex-direction:column;gap:34px}.ghead{display:flex;align-items:center;gap:9px;margin-bottom:12px;font-family:"DM Sans"}.ghead>span{font-size:17px}.ghead strong{font-size:13px;letter-spacing:.13em;text-transform:uppercase}.ghead small{font-size:10px;color:#a1a1aa;font-style:italic}.ghead i{font-size:10px;color:#a1a1aa;font-style:normal}.ghead hr{flex:1;border:0;border-top:1px solid rgba(239,68,68,.14);margin-left:5px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.card{position:relative;text-align:left;padding:17px;border-radius:17px;min-height:190px;display:flex;flex-direction:column;transition:transform .28s cubic-bezier(.4,0,.2,1),box-shadow .28s,border-color .28s}.card:hover{transform:translateY(-4px);border-color:rgba(239,68,68,.4);box-shadow:0 14px 34px rgba(239,68,68,.13)}.glass-touch:hover{background-image:linear-gradient(135deg,rgba(254,226,226,.8),rgba(254,202,202,.5))}.ctop{display:flex;justify-content:space-between;color:#a1a1aa;font:10px "DM Sans"}.card h3{font:700 18px "PT Sans";margin-top:16px}.card>small{color:#ef4444;font:600 10px "DM Sans";text-transform:uppercase;letter-spacing:.1em;margin-top:3px}.card p{font:13px/1.55 "DM Sans";color:#71717a;margin-top:9px}.cfoot{margin-top:auto;padding-top:14px;display:flex;justify-content:space-between;align-items:center}.cfoot em{font:600 9px "DM Sans";font-style:normal;text-transform:uppercase;padding:3px 7px;border:1px solid #d4d4d8;color:#71717a;border-radius:99px}.cfoot .s-high,.cfoot .s-critical{color:#ef4444;border-color:rgba(239,68,68,.35)}.cfoot .s-medium{color:#ca8a04;border-color:rgba(202,138,4,.3)}
.toolview{padding-top:12px}.back{font:600 12px "DM Sans";color:#ef4444;margin-bottom:14px}.tooltitle{border-radius:18px;padding:20px;margin-bottom:16px}.tooltitle h2{font:700 30px "PT Sans";margin-top:5px}.tooltitle p{font:14px "DM Sans";color:#71717a;margin-top:5px}
footer{max-width:1152px;margin:auto;border-top:1px solid rgba(239,68,68,.10);padding:22px 24px 28px;display:flex;justify-content:space-between;gap:20px;font:11px "DM Sans";color:#71717a}
@media(max-width:900px){.navlinks{display:none}.hero{grid-template-columns:1fr;padding:30px 0}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.intro{grid-template-columns:1fr}.nav{padding:0 16px}main{padding:24px 16px 55px}}
@media(max-width:520px){.navmeta span:first-child{display:none}.brand{font-size:18px}.hero h1{font-size:43px}.hero p{font-size:14px}.hero-actions{flex-wrap:wrap}.grid{grid-template-columns:1fr}.card{min-height:160px}.stats{gap:10px}.ghead small{display:none}footer{padding:18px 16px;flex-direction:column}.termbody{min-height:210px;padding:18px}}
</style>