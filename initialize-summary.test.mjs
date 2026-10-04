import test from 'node:test';import assert from 'node:assert/strict';import {inspect} from './inspect-auth.mjs';import {summarizeInitialization} from './initialize-summary.mjs';
const config={mcpHost:'mail-123456.zohomcp.com',mcpUrl:'https://mail-123456.zohomcp.com/mcp/SYNTHETIC_ENDPOINT_KEY/message'};
const initialized={jsonrpc:'2.0',id:1,result:{protocolVersion:'2025-03-26',capabilities:{tools:{}},serverInfo:{name:config.mcpUrl,version:'synthetic-token'}}};
test('successful secret-endpoint initialization is recognized without requiring OAuth challenge',async()=>{
 let calls=0;const result=await inspect(config,async(url,init)=>{calls++;assert.equal(String(url),config.mcpUrl);assert.equal(init.method,'POST');assert.equal(init.headers.Accept,'application/json, text/event-stream');assert.equal(JSON.parse(init.body).method,'initialize');return Response.json(initialized)});assert.equal(calls,1);assert.equal(result.status,'mcp_initialized');assert.equal(result.httpStatus,200);assert.equal(result.contentType,'application/json');assert(!JSON.stringify(result).includes('SYNTHETIC_ENDPOINT_KEY'));assert(!JSON.stringify(result).includes('synthetic-token'));
});
test('SSE notifications followed by split UTF8 initialize result are parsed and stream cancelled',async()=>{
 let cancelled=false;const encoded=new TextEncoder().encode('event: message\r\ndata: '+JSON.stringify({jsonrpc:'2.0',method:'notifications/test',params:{text:'é synthetic-secret'}})+'\r\n\r\nevent: message\r\ndata: '+JSON.stringify(initialized)+'\r\n\r\n');let offset=0;
 const stream=new ReadableStream({pull(c){if(offset<encoded.length){c.enqueue(encoded.slice(offset,offset+3));offset+=3;}},cancel(){cancelled=true;}});const result=await summarizeInitialization(new Response(stream,{headers:{'content-type':'text/event-stream'}}));assert.equal(result.status,'mcp_initialized');assert.equal(cancelled,true);assert(!JSON.stringify(result).includes('secret'));
});
test('HTTP errors, HTML and redirects disclose only numeric status and fixed mime category',async()=>{
 const result=await summarizeInitialization(new Response(config.mcpUrl,{status:404,headers:{'content-type':'text/html; secret=synthetic-token'}}));assert.deepEqual(result,{httpStatus:404,contentType:'text/html',ok:false,status:'provider_http_error'});assert.equal((await summarizeInitialization(new Response(null,{status:307,headers:{location:config.mcpUrl}}))).status,'redirect_denied');
});
test('JSON-RPC errors ignore arbitrary messages/data and unknown code values',async()=>{
 const result=await summarizeInitialization(Response.json({jsonrpc:'2.0',id:1,error:{code:-32602,message:config.mcpUrl,data:{token:'synthetic-token'}}}));assert.equal(result.mcpCategory,'invalid_params');assert(!JSON.stringify(result).includes('synthetic'));const unknown=await summarizeInitialization(Response.json({jsonrpc:'2.0',id:1,error:{code:123456,message:config.mcpUrl}}));assert.equal(unknown.mcpCategory,'provider_error');assert(!JSON.stringify(unknown).includes('123456'));
});
test('bounded bodies and missing/wrong result cannot imply live mailbox authorization',async()=>{
 assert.equal((await summarizeInitialization(Response.json({padding:'x'.repeat(66000)}))).status,'response_limit');assert.equal((await summarizeInitialization(new Response(null,{status:202}))).status,'initialize_result_missing');assert.equal((await summarizeInitialization(Response.json({...initialized,id:2}))).status,'protocol_response_unrecognized');
});
