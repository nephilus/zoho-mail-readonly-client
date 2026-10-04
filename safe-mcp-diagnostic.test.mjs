import test from 'node:test';import assert from 'node:assert/strict';
import {guardedFetch,safeLocalError} from './local.mjs';import {ownerReadCheck} from './owner-read-check.mjs';import {retryDelay,httpDiagnostic,toolDiagnostic} from './safe-mcp-diagnostic.mjs';
const config={mcpUrl:'https://mcp.zoho.com/mcp/SYNTHETIC_SECRET_KEY',primaryEmail:'owner@example.test'};
const initialize={method:'POST',body:JSON.stringify({method:'initialize'})};
test('MCP tool errors disclose recognized code without inventing HTTP status or raw text',()=>{
 const result=toolDiagnostic({isError:true,content:[{type:'text',text:JSON.stringify({error:'invalid_scope',message:config.mcpUrl})}]});assert.equal(result.errorCode,'invalid_scope');assert.equal(result.httpStatus,null);assert.equal(result.transportStage,'tool_call');assert(!JSON.stringify(result).includes('SYNTHETIC'));
 assert.equal(toolDiagnostic({content:[{type:'text',text:JSON.stringify({error:'SECRET_UNKNOWN_CODE'})}]}).errorCode,null);
});
test('HTTP failures preserve safe status/stage/MIME/code and never arbitrary response or headers',async()=>{
 for(const status of [400,404,405,409,429,500,502,503,401,403]){
  let safe;try{await guardedFetch(config,async()=>Response.json({error:{code:'invalid_scope',message:config.mcpUrl},accountId:'123',mail:'PRIVATE_BODY'},{status,headers:{'retry-after':'30','location':config.mcpUrl,'www-authenticate':config.mcpUrl,'x-secret':config.mcpUrl}}))(config.mcpUrl,initialize)}catch(error){safe=safeLocalError(error)}
  assert.equal(safe.status,[401,403].includes(status)?'mcp_authorization_required':'provider_rejected');assert.deepEqual(safe.diagnostic,{transportStage:'initialize',httpStatus:status,contentType:'application/json',retryAfterSeconds:30,errorCode:'invalid_scope',requestedTransport:'streamable_http',endpointPattern:'mcp_key'});
  for(const value of ['SYNTHETIC_SECRET_KEY','PRIVATE_BODY','123','www-authenticate','x-secret'])assert(!JSON.stringify(safe).includes(value));
 }
 const get=await guardedFetch(config,async()=>new Response(null,{status:405}))(config.mcpUrl,{method:'GET'});assert.equal(get.status,405);
});
test('stage identifies discovery/call; timeout and network failure remain distinct with no raw exception',async()=>{
 for(const [method,stage]of [['tools/list','tool_inventory'],['tools/call','tool_call']]){
  const req={method:'POST',body:JSON.stringify({method,params:{name:'getMailAccounts'}})};try{await guardedFetch(config,async()=>new Response(config.mcpUrl,{status:404,headers:{'content-type':'text/html'}}))(config.mcpUrl,req)}catch(error){assert.equal(safeLocalError(error).diagnostic.transportStage,stage);assert.equal(safeLocalError(error).diagnostic.contentType,'text/html');}
 }
 for(const name of ['TypeError','AbortError','TimeoutError']){const error=Object.assign(Error(config.mcpUrl),{name});let safe;try{await guardedFetch(config,async()=>{throw error})(config.mcpUrl,initialize)}catch(e){safe=safeLocalError(e)}assert.equal(safe.status,name==='TypeError'?'network_error':'timeout');assert.equal(safe.diagnostic.httpStatus,null);assert(!JSON.stringify(safe).includes('SYNTHETIC'));}
});
test('unrecognized/error-shaped secrets and oversized/HTML bodies never enter diagnostic',async()=>{
 for(const response of [Response.json({error:config.mcpUrl},{status:500}),new Response(config.mcpUrl,{status:500,headers:{'content-type':'text/html','retry-after':config.mcpUrl}}),Response.json({error:'invalid_scope',padding:'x'.repeat(9000)},{status:500})]){const diagnostic=await httpDiagnostic(response,'initialize');assert.equal(diagnostic.errorCode,null);assert(!JSON.stringify(diagnostic).includes('SYNTHETIC'));}
});
test('retry delay accepts bounded seconds or standard future HTTP date only',()=>{
 const now=Date.UTC(2026,9,4,20,0);assert.equal(retryDelay('15',now),15);assert.equal(retryDelay('Sun, 04 Oct 2026 20:00:30 GMT',now),30);
 for(const value of ['9999999','-1','1.5','private-token','Sun, 04 Oct 2026 19:00:00 GMT',config.mcpUrl])assert.equal(retryDelay(value,now),null);
});
test('owner check carries transport diagnostic in one pass and makes no mailbox call',async()=>{
 let calls=0;const result=await ownerReadCheck(config,{fetcher:async()=>{calls++;return Response.json({error:'invalid_request'},{status:400})}});assert.equal(result.status,'provider_rejected');assert.equal(result.transportDiagnostic.httpStatus,400);assert.equal(result.transportDiagnostic.transportStage,'initialize');assert.equal(result.ownerMatched,false);assert.equal(calls,1);assert(!JSON.stringify(result).includes('SYNTHETIC'));
});
