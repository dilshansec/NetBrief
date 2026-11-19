/* Shared pure filtering helpers used by the UI and regression checks. */
(function(root){
 function parseNumbers(value){
  if(!value.trim())return [];
  return value.split(',').map(part=>{const m=part.trim().match(/^(\d+)(?:\s*-\s*(\d+))?$/);if(!m)throw Error('Use packet numbers such as 345-347, 352.');const a=Number(m[1]),b=Number(m[2]||m[1]);if(!Number.isSafeInteger(a)||!Number.isSafeInteger(b)||a<1||b<a)throw Error('Packet ranges must start at 1 or higher and end after they start.');return [a,b];});
 }
 function matches(p,f){return (!f.ids||f.ids.has(p.no))&&(!f.ranges.length||f.ranges.some(([a,b])=>p.no>=a&&p.no<=b))&&(!f.protocol||p.protocol===f.protocol)&&(f.connection===''||p.connection_id===Number(f.connection))&&(!f.ip||p.src.toLowerCase()===f.ip.toLowerCase()||p.dst.toLowerCase()===f.ip.toLowerCase())&&(f.port===''||p.sport===Number(f.port)||p.dport===Number(f.port))&&(!f.flag||(p.flags||[]).includes(f.flag))&&(!f.query||Object.values(p).some(v=>v!==null&&String(v).toLowerCase().includes(f.query)));}
 function rangesFor(ids){const nums=[...new Set(ids)].sort((a,b)=>a-b),out=[];for(const n of nums){const last=out[out.length-1];if(last&&n===last[1]+1)last[1]=n;else out.push([n,n]);}return out;}
 function label(ids){return rangesFor(ids).map(([a,b])=>a===b?'#'+a:'#'+a+'-'+b).join(', ');}
 function wire(ranges){return ranges.map(([a,b])=>a===b?'frame.number == '+a:'(frame.number >= '+a+' && frame.number <= '+b+')').join(' || ');}
 const api={parseNumbers,matches,rangesFor,label,wire};root.PacketFilters=api;if(typeof module!=='undefined')module.exports=api;
})(typeof globalThis!=='undefined'?globalThis:this);
