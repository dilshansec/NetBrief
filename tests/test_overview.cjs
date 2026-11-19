const assert=require('node:assert/strict');
const {communications}=require('../static/overview.js');
const rows=communications([
 {a:'10.0.0.1',b:'10.0.0.2',protocol:'TCP',packets:1000,bytes:2000},
 {a:'10.0.0.2',b:'10.0.0.1',protocol:'UDP',packets:5,bytes:100},
 {a:'10.0.0.1',b:'10.0.0.2',protocol:'TCP',a_port:1234,b_port:443,packets:8,bytes:200},
 {a:'10.0.0.1',b:'10.0.0.3',protocol:'ICMP',packets:2,bytes:40},
]);
assert.equal(rows.length,2);
assert.equal(rows[0].packets,1013);
assert.equal(rows[0].bytes,2300);
assert.deepEqual(rows[0].protocols,['TCP','UDP']);
assert.deepEqual(communications([]),[]);
console.log('Communication grouping passed');

const {packetRanges}=require('../static/overview.js');
assert.equal(packetRanges([9,2,1,3,7,7,10]),'1–3, 7, 9–10');
assert.equal(packetRanges([4]),'4');
assert.equal(packetRanges([]),'');
console.log('Exact evidence ranges passed');
