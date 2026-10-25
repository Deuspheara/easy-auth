'use strict';
const http=require('node:http');
const assert=require('node:assert/strict');
async function start() {
  let queued=[],waiting=[],failure;
  const server=http.createServer((request,response) => {
    const headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'none'"};
    try {
      assert.equal(request.method,'GET');assert.equal(request.headers.cookie,undefined);
      assert.equal(request.headers.authorization,undefined);
      assert.ok(request.url.length<=8192);
      const url=new URL(request.url,'http://127.0.0.1');
      if(url.pathname==='/done') {response.writeHead(200,{...headers,'Content-Type':'text/html'});response.end('<!doctype html><title>Owned native return</title>');return;}
      assert.equal(url.pathname,'/callback');
      if(waiting.length)waiting.shift().resolve(url);else queued.push(url);
      response.writeHead(303,{...headers,Location:'/done'});response.end();
    } catch {failure=new Error('owned loopback request');response.writeHead(400,headers);response.end();}
  });
  await new Promise((resolve,reject) => {server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const origin='http://127.0.0.1:'+server.address().port;
  return {origin,redirect:origin+'/callback',
    next() {if(failure)return Promise.reject(failure);if(queued.length)return Promise.resolve(queued.shift());return new Promise((resolve,reject) => waiting.push({resolve,reject}));},
    async close() {for(const item of waiting)item.reject(new Error('owned loopback closed'));waiting=[];queued=[];server.closeAllConnections();await new Promise(resolve=>server.close(resolve));if(failure)throw failure;}
  };
}
module.exports={start};
