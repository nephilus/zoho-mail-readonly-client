import test from 'node:test';import assert from 'node:assert/strict';import {mcpEndpoint} from './mcp-policy.mjs';import {guardedFetch,endpoint} from './local.mjs';import {inspect} from './inspect-auth.mjs';
const config={mcpHost:'mail-123456.zohomcp.com',mcpUrl:'https://mail-123456.zohomcp.com/mcp/SYNTHETIC_ENDPOINT_KEY/message'};
test('exact trusted owner pin accepted by client and inspection policy',async()=>{
 assert.equal(mcpEndpoint(config).hostname,config.mcpHost);assert.equal(endpoint(config.mcpUrl,config.mcpHost).hostname,config.mcpHost);
 assert.equal((await inspect(config,async()=>new Response(null,{status:401}))).status,'resource_metadata_not_advertised');
});
test('lookalikes, subdomains, other tenants, ports, userinfo and insecure protocols refused before transmission',async()=>{
 for(const url of ['https://mail-123456.zohomcp.com.evil.example/mcp/key/message','https://child.mail-123456.zohomcp.com/mcp/key/message','https://mail-654321.zohomcp.com/mcp/key/message','https://mail-123456.zohomcp.com:8443/mcp/key/message','https://user:password@mail-123456.zohomcp.com/mcp/key/message','http://mail-123456.zohomcp.com/mcp/key/message']){
  const candidate={...config,mcpUrl:url};assert.throws(()=>mcpEndpoint(candidate));let calls=0;await assert.rejects(inspect(candidate,async()=>{calls++;throw Error()}));assert.equal(calls,0);
 }
 assert.throws(()=>mcpEndpoint({...config,mcpHost:'*.zohomcp.com'}));assert.throws(()=>mcpEndpoint({...config,mcpHost:'attacker.example'}));
});
test('private endpoint and bearer token cannot follow redirects or reach another origin/path',async()=>{
 let calls=0;const guarded=guardedFetch({...config,mcpBearerToken:'synthetic-token'},async()=>{calls++;return new Response(null,{status:302,headers:{location:'https://accounts.zoho.com/'}})});
 await assert.rejects(guarded(config.mcpUrl));assert.equal(calls,1);
 for(const url of ['https://accounts.zoho.com/','https://mail-654321.zohomcp.com/','https://mail-123456.zohomcp.com/another-path'])await assert.rejects(guarded(url,{headers:{Authorization:'Bearer synthetic-token'}}));assert.equal(calls,1);
});
test('resource metadata cannot cross owner origin, and authorization metadata receives no credentials',async()=>{
 let calls=0;await assert.rejects(inspect(config,async()=>{calls++;return new Response(null,{status:401,headers:{'www-authenticate':'Bearer resource_metadata="https://mail-654321.zohomcp.com/metadata"'}})}));assert.equal(calls,1);
 calls=0;const resourceURL='https://mail-123456.zohomcp.com/metadata';const result=await inspect({...config,mcpBearerToken:'synthetic-token'},async(url,init)=>{calls++;assert.equal(init.headers?.Authorization,undefined);if(calls>1)assert.equal(String(url).includes('SYNTHETIC_ENDPOINT_KEY'),false);if(calls===1)return new Response(null,{status:401,headers:{'www-authenticate':`Bearer resource_metadata="${resourceURL}"`}});if(calls===2)return Response.json({resource:config.mcpUrl,authorization_servers:['https://accounts.zoho.com/']});return Response.json({issuer:'https://accounts.zoho.com/',grant_types_supported:['refresh_token'],code_challenge_methods_supported:['S256']});});assert.equal(result.status,'metadata_inspected');assert.equal(calls,3);
});
