// Owned isolated Chromium diagnostic. No access to the user's browser profiles.
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
const [profile, expected] = process.argv.slice(2);
const deadline = setTimeout(() => { console.log(JSON.stringify({state:'failed',error:'Browser diagnostic timeout.'})); process.exit(1); }, 20000);
let socket;
function publicAddress(value) {
  if (net.isIP(value) === 4) {
    const [a,b] = value.split('.').map(Number);
    return !(a===0 || a===10 || a===127 || a>=224 || (a===169&&b===254) || (a===172&&b>=16&&b<=31) || (a===192&&b===168) || (a===100&&b>=64&&b<=127) || (a===198&&(b===18||b===19)));
  }
  if (net.isIP(value) === 6) {
    const v=value.toLowerCase();
    return !(v==='::' || v==='::1' || v.startsWith('fc') || v.startsWith('fd') || /^fe[89ab]/.test(v) || v.startsWith('ff') || v.startsWith('::ffff:'));
  }
  return false;
}
try {
  const portFile=path.join(profile,'DevToolsActivePort');
  let lines;
  for(let i=0;i<80;i++) {
    try { lines=fs.readFileSync(portFile,'utf8').trim().split(/\r?\n/); if(Number(lines[0])>0) break; } catch {}
    await new Promise(r=>setTimeout(r,100));
  }
  if(!lines) throw new Error('Edge debugging endpoint unavailable.');
  socket=new WebSocket(`ws://127.0.0.1:${Number(lines[0])}${lines[1]}`);
  await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',()=>reject(new Error('Local browser connection failed.')),{once:true});});
  let nextId=0; const pending=new Map();
  socket.addEventListener('message',e=>{const m=JSON.parse(e.data);if(m.id&&pending.has(m.id)){const p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(new Error(m.error.message)):p.resolve(m.result);}});
  function command(method,params={},sessionId) {
    const id=++nextId;
    return new Promise((resolve,reject)=>{pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}: {})}));});
  }
  const target=await command('Target.createTarget',{url:'about:blank'});
  const attached=await command('Target.attachToTarget',{targetId:target.targetId,flatten:true});
  const probe=await command('Runtime.evaluate',{awaitPromise:true,returnByValue:true,expression:`(async()=>{
    const pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'},{urls:'stun:stun.cloudflare.com:3478'}]});
    const candidates=[];
    try {
      const gathered=new Promise(resolve=>{const timer=setTimeout(resolve,6500);pc.onicecandidate=e=>{if(!e.candidate){clearTimeout(timer);resolve();}else candidates.push({address:e.candidate.address,type:e.candidate.type});};});
      pc.createDataChannel('diagnostic');await pc.setLocalDescription(await pc.createOffer());await gathered;
      return {candidates};
    }finally{pc.close();}
  })()`},attached.sessionId);
  if(probe.exceptionDetails) throw new Error('WebRTC probe could not run.');
  const candidates=probe.result.value.candidates;
  const publicIPs=[...new Set(candidates.map(c=>c.address).filter(publicAddress))];
  const httpProbe=await command('Runtime.evaluate',{awaitPromise:true,returnByValue:true,expression:`(async()=>{
    return await Promise.all([
      ['https://api.anthropic.com/cdn-cgi/trace',true],
      ['https://claude.ai/cdn-cgi/trace',true],
      ['https://www.baidu.com',false]
    ].map(async([url,trace])=>{
      try{
        const response=await fetch(url,{mode:trace?'cors':'no-cors',signal:AbortSignal.timeout(3500)});
        if(!trace)return {host:new URL(url).host,reachable:true,opaque:response.type==='opaque'};
        if(!response.ok)throw new Error('HTTP '+response.status);
        const body=await response.text();const ip=body.match(/^ip=(.+)$/m)?.[1]?.trim();const country=body.match(/^loc=(.+)$/m)?.[1]?.trim();
        return {host:new URL(url).host,reachable:true,ip,country};
      }catch(error){return {host:new URL(url).host,reachable:false,error:error.message};}
    }));
  })()`},attached.sessionId);
  const HTTPTests=httpProbe.result?.value||[];
  const different=publicIPs.filter(ip=>ip!==expected);
  console.log(JSON.stringify({state:publicIPs.length?(different.length?'warning':'observed-match'):'inconclusive',publicIPs,observedCount:candidates.length,scope:'isolated-browser-explicit-http-proxy',differentCount:different.length,HTTPTests}));
} catch(error) { console.log(JSON.stringify({state:'failed',error:error.message,scope:'isolated-browser-explicit-http-proxy'})); process.exitCode=1; }
finally {clearTimeout(deadline);if(socket)socket.close();}