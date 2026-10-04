import test from 'node:test';import assert from 'node:assert/strict';
import {execute,guardedFetch,sanitize,safeLocalError} from './local.mjs';
const config={mcpUrl:'https://mcp.zoho.com/fixture?key=SYNTHETIC_ENDPOINT_KEY',accountId:'123',primaryEmail:'owner@example.test',dmarcDomain:'example.test',dmarcFolderId:'456'};
const tool=(name,properties={})=>({name,inputSchema:{type:'object',properties,additionalProperties:false},annotations:{readOnlyHint:true,destructiveHint:false}});
function fixture({extraTool,wrongAccount=false,providerError=false}={}){
 const calls=[];const fetcher=async(url,init)=>{
  assert.equal(String(url),config.mcpUrl);assert.equal(init.redirect,'manual');assert.ok(init.signal);if(init.method==='GET')return new Response(null,{status:405});if(init.method==='DELETE')return new Response(null,{status:204});
  const rpc=JSON.parse(init.body);calls.push(rpc);if(rpc.method==='notifications/initialized')return new Response(null,{status:202});
  let result;if(rpc.method==='initialize')result={protocolVersion:'2025-06-18',capabilities:{tools:{}},serverInfo:{name:'fixture',version:'1'}};
  if(rpc.method==='tools/list')result={tools:[tool('getMailAccounts'),tool('listEmails',{accountId:{type:'string'},limit:{type:'integer'}}),...(extraTool?[tool(extraTool)]:[])]};
  if(rpc.method==='tools/call')result=providerError?{isError:true,content:[{type:'text',text:config.mcpUrl}]}:{content:[{type:'text',text:JSON.stringify(rpc.params.name==='getMailAccounts'?{data:[{accountId:'123',primaryEmailAddress:wrongAccount?'other@example.test':config.primaryEmail}]}:[{subject:'Synthetic fixture',access_token:'DO_NOT_RETURN',text:'SYNTHETIC_ENDPOINT_KEY'}])}]};
  return Response.json({jsonrpc:'2.0',id:rpc.id,result});
 };return {fetcher,calls};
}
test('real official SDK discovers and calls only approved reads with verified primary account',async()=>{
 const f=fixture();const result=await execute(config,{action:'call',name:'listEmails',arguments:{accountId:'123',limit:1}},f);assert.equal(result.ok,true);assert.ok(!JSON.stringify(result).includes('DO_NOT_RETURN'));assert.ok(!JSON.stringify(result).includes('SYNTHETIC_ENDPOINT_KEY'));assert.deepEqual(f.calls.filter(c=>c.method==='tools/call').map(c=>c.params.name),['getMailAccounts','listEmails']);
});
test('write tool calls and provider servers with additional write tools fail closed',async()=>{
 const f=fixture();await assert.rejects(execute(config,{action:'call',name:'sendEmail',arguments:{}},f));assert.equal(f.calls.length,0);
 await assert.rejects(execute(config,{action:'list_tools'},fixture({extraTool:'sendEmail'})));
});
test('wrong primary/account, unsafe paging and mark-read parameters cannot reach requested read',async()=>{
 await assert.rejects(execute(config,{action:'call',name:'listEmails',arguments:{accountId:'123'}},fixture({wrongAccount:true})));
 for(const args of [{accountId:'999'},{accountId:'123',limit:51},{accountId:'123',markRead:true},{}]){const f=fixture();await assert.rejects(execute(config,{action:'call',name:'listEmails',arguments:args},f));assert.ok(!f.calls.some(c=>c.method==='tools/call'&&c.params.name==='listEmails'));}
});
test('auth challenges, redirects, provider tool errors and raw exceptions produce no endpoint secret',async()=>{
 for(const fetcher of [async()=>new Response(config.mcpUrl,{status:401}),async()=>new Response(null,{status:302,headers:{Location:'https://evil.test'}}),async()=>{throw Error(config.mcpUrl);}]){try{await execute(config,{action:'list_tools'},{fetcher});assert.fail();}catch(e){assert.ok(!JSON.stringify(safeLocalError(e)).includes('SYNTHETIC'));}}
 await assert.rejects(execute(config,{action:'call',name:'listEmails',arguments:{accountId:'123'}},fixture({providerError:true})));
});
test('endpoint and protocol guard deny SSRF, alternate hosts, writes and redirects before transmission',async()=>{
 let calls=0;const fetcher=guardedFetch(config,async()=>{calls++;return Response.json({});});
 for(const url of ['http://mcp.zoho.com/fixture','https://mcp.zoho.com.evil.test/','https://127.0.0.1/','https://mcp.zoho.com/other'])await assert.rejects(fetcher(url,{method:'GET'}));
 await assert.rejects(fetcher(config.mcpUrl,{method:'POST',body:JSON.stringify({method:'tools/call',params:{name:'deleteEmail'}})}));assert.equal(calls,0);
});
test('stream byte cap rejects large responses and credential-shaped values are redacted recursively',async()=>{
 const fetcher=guardedFetch(config,async()=>new Response(new Uint8Array(1500001)));await assert.rejects((await fetcher(config.mcpUrl,{method:'GET'})).arrayBuffer());
 const output=sanitize({access_token:'private',nested:{clientSecret:'private',safe:config.mcpUrl},text:'SYNTHETIC_ENDPOINT_KEY'},config);assert.ok(!JSON.stringify(output).includes('private'));assert.ok(!JSON.stringify(output).includes('SYNTHETIC_ENDPOINT_KEY'));
});
test('DMARC cannot override pinned folder or select another domain through tool arguments',async()=>{
 let calls=0;await assert.rejects(execute(config,{action:'dmarc',messageId:'9',folderId:'999'},{fetcher:async()=>{calls++;throw Error();}}));assert.equal(calls,0);
});
