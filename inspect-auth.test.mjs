import test from 'node:test';import assert from 'node:assert/strict';import {inspect} from './inspect-auth.mjs';
const config={mcpUrl:'https://mcp.zoho.com/server/synthetic-private-key'};
const resourceURL='https://mcp.zoho.com/.well-known/oauth-protected-resource/server';
test('unauthorized endpoint without metadata returns fixed safe result',async()=>{
 const result=await inspect(config,async()=>new Response('synthetic-secret',{status:401}));assert.deepEqual(result,{ok:false,status:'resource_metadata_not_advertised'});assert(!JSON.stringify(result).includes('synthetic'));
});
test('discovery uses only initialize and GET, without authorization forwarding',async()=>{
 const calls=[];const result=await inspect(config,async(url,init)=>{calls.push(String(url));assert.equal(init.redirect,'manual');assert.equal(init.headers?.Authorization,undefined);
 if(calls.length===1){assert.equal(JSON.parse(init.body).method,'initialize');return new Response(null,{status:401,headers:{'www-authenticate':`Bearer resource_metadata="${resourceURL}"`}})}
 if(calls.length===2)return Response.json({resource:config.mcpUrl,authorization_servers:['https://mcp.zoho.com/']});
 return Response.json({issuer:'https://mcp.zoho.com/',authorization_endpoint:'https://mcp.zoho.com/auth',token_endpoint:'https://mcp.zoho.com/token',registration_endpoint:'https://mcp.zoho.com/register',grant_types_supported:['authorization_code','refresh_token'],code_challenge_methods_supported:['S256']});
 });assert.equal(calls.length,3);assert.equal(result.pkceS256,true);assert.equal(result.refresh,true);assert(!JSON.stringify(result).includes('https:'));
});
test('off-origin metadata is blocked before any follow-up request',async()=>{
 let calls=0;await assert.rejects(inspect(config,async()=>{calls++;return new Response(null,{status:401,headers:{'www-authenticate':'Bearer resource_metadata="https://attacker.example/secret"'}})}));assert.equal(calls,1);
});
test('redirects and issuer mismatch fail closed',async()=>{
 assert.equal((await inspect(config,async()=>new Response(null,{status:302}))).status,'redirect_denied');
 let calls=0;const result=await inspect(config,async()=>{calls++;if(calls===1)return new Response(null,{status:401,headers:{'www-authenticate':`Bearer resource_metadata="${resourceURL}"`}});if(calls===2)return Response.json({resource:config.mcpUrl,authorization_servers:['https://mcp.zoho.com/']});return Response.json({issuer:'https://accounts.zoho.com/'});});assert.equal(result.status,'issuer_mismatch');
});
