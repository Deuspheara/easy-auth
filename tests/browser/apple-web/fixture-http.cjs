'use strict';
const https=require('node:https');

// Node requests do not inherit Chromium's host resolver. Connect only to this
// owned proxy's loopback port with its exact virtual Host. Never print payloads.
function request(origin,path,body) {
  const target=new URL(origin);
  if(target.protocol!=='https:'||target.hostname!=='app.example'||!target.port) throw new Error('Invalid owned origin');
  const encoded=body===undefined?null:JSON.stringify(body);
  return new Promise((resolve,reject)=>{
    const headers={Host:target.host};
    if(encoded) Object.assign(headers,{Origin:origin,'Content-Type':'application/json','Content-Length':Buffer.byteLength(encoded)});
    const operation=https.request({hostname:'127.0.0.1',port:target.port,servername:'app.example',rejectUnauthorized:false,path,method:encoded?'POST':'GET',headers},response=>{
      const chunks=[];let bytes=0;
      response.on('data',chunk=>{bytes+=chunk.length;if(bytes>262144)response.destroy();else chunks.push(chunk);});
      response.on('error',()=>reject(new Error('Owned fixture response failed')));
      response.on('end',()=>resolve({status:response.statusCode,text:Buffer.concat(chunks).toString('utf8')}));
    });
    operation.on('error',()=>reject(new Error('Owned fixture request failed')));
    operation.setTimeout(5000,()=>operation.destroy());
    operation.end(encoded);
  });
}
module.exports={request};
