/* A communication is one unordered IP pair, across ports and protocols. */
(function(root){
 function communications(flows){
  const pairs=new Map();
  for(const f of flows){
   const [a,b]=[f.a,f.b].sort(),key=JSON.stringify([a,b]);
   if(!pairs.has(key))pairs.set(key,{a,b,packets:0,bytes:0,protocols:new Set()});
   const pair=pairs.get(key);pair.packets+=f.packets;pair.bytes+=f.bytes;pair.protocols.add(f.protocol);
  }
  return [...pairs.values()].map(p=>({...p,protocols:[...p.protocols].sort()})).sort((a,b)=>b.bytes-a.bytes);
 }
 function packetRanges(numbers){
  const sorted=[...new Set(numbers)].sort((a,b)=>a-b), ranges=[];
  for(let i=0;i<sorted.length;i++){
   const start=sorted[i];let end=start;
   while(i+1<sorted.length&&sorted[i+1]===end+1)end=sorted[++i];
   ranges.push(start===end?String(start):`${start}–${end}`);
  }
  return ranges.join(', ');
 }
 const api={communications,packetRanges};
 if(typeof module!=='undefined')module.exports=api;else root.NetSentryOverview=api;
})(globalThis);
