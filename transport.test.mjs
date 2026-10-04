import test from 'node:test';
import assert from 'node:assert/strict';
import {createTransport as transportFactory,safeDiagnostic,createTokenCache} from './transport.mjs';
const createTransport=(env,fetcher,cache=createTokenCache())=>transportFactory(env,fetcher,cache);
const env={ZOHO_REGION:'us',ZOHO_CLIENT_ID:'synthetic-id',ZOHO_CLIENT_SECRET:'synthetic-secret',ZOHO_REFRESH_TOKEN:'synthetic-refresh',ZOHO_ACCOUNT_ID:'123',ZOHO_PRIMARY_EMAIL:'owner@example.test'};
test('attachment transport allows only pinned report folder and bounded binary reads',async()=>{
 let calls=0;const folder='123456789';const fetcher=async url=>{calls++;const path=new URL(url).pathname;if(path.endsWith('/token'))return Response.json({access_token:'test'});if(path==='/api/accounts')return Response.json({data:[{accountId:'123',primaryEmailAddress:env.ZOHO_PRIMARY_EMAIL}]});return new Response('report');};
 const transport=createTransport({...env,DMARC_FOLDER_ID:folder},fetcher);
 await assert.rejects(transport({method:'GET',path:'/api/accounts/123/folders/99/messages/2/attachments/3',query:{},binary:true}));assert.equal(calls,0);
 await assert.rejects(transport({method:'GET',path:`/api/accounts/123/folders/${folder}/messages/2/attachmentinfo`,query:{},binary:true}));assert.equal(calls,0);
 const result=await transport({method:'GET',path:`/api/accounts/123/folders/${folder}/messages/2/attachments/3`,query:{},binary:true});assert.equal(new TextDecoder().decode(result),'report');assert.equal(calls,3);
 const tooLarge=createTransport({...env,DMARC_FOLDER_ID:folder},async url=>String(url).endsWith('/token')?Response.json({access_token:'test'}):String(url).endsWith('/api/accounts')?Response.json({data:[{accountId:'123',primaryEmailAddress:env.ZOHO_PRIMARY_EMAIL}]}):new Response(new Uint8Array(512001)));
 await assert.rejects(tooLarge({method:'GET',path:`/api/accounts/123/folders/${folder}/messages/2/attachments/3`,query:{},binary:true}));
});
test('cache reuses token, shares concurrent refresh, expires early and resets on credential rotation',async()=>{
 let time=0,loads=0;const cache=createTokenCache(()=>time);const identity=['client','secret','refresh'];
 const load=async()=>{loads++;return {access_token:'synthetic-'+loads,expires_in:3600};};
 const values=await Promise.all([cache.get(identity,load),cache.get(identity,load),cache.get(identity,load)]);assert.equal(loads,1);assert.ok(values.every(v=>v===values[0]));
 time=3500000;await cache.get(identity,load);assert.equal(loads,1);
 time=3540000;await cache.get(identity,load);assert.equal(loads,2);
 await cache.get(['client','changed-secret','refresh'],load);assert.equal(loads,3);
});
test('sequential tool calls reuse refresh while keeping mailbox responses uncached',async()=>{
 let refreshes=0,reads=0;const cache=createTokenCache();
 const fetcher=async url=>{if(String(url).includes('/oauth/v2/token')){refreshes++;return Response.json({access_token:'test',expires_in:3600});}if(String(url).endsWith('/api/accounts'))return Response.json({data:[{accountId:'123',primaryEmailAddress:env.ZOHO_PRIMARY_EMAIL}]});reads++;return Response.json({data:[]});};
 for(let i=0;i<3;i++)await createTransport(env,fetcher,cache)({method:'GET',path:'/api/accounts/123/messages/view',query:{}});
 assert.equal(refreshes,1);assert.equal(reads,3);
});
test('known refresh throttling is held for ten minutes without repeated credential requests',async()=>{
 let time=0,calls=0;const cache=createTokenCache(()=>time);const fetcher=async()=>{calls++;return Response.json({error:'Access Denied',error_description:'PRIVATE_DESCRIPTION'},{status:400});};
 const run=()=>createTransport(env,fetcher,cache)({method:'GET',path:'/api/accounts/123/messages/view',query:{}});
 await assert.rejects(run());time=599999;await assert.rejects(run());assert.equal(calls,1);
 time=600001;await assert.rejects(run());assert.equal(calls,2);
});
test('refresh uses form body without URL secrets and Mail uses fixed GET with matched primary account',async()=>{
 const calls=[];const fetcher=async(url,init)=>{calls.push({url:String(url),...init});return Response.json(calls.length===1?{access_token:'synthetic-access'}:calls.length===2?{status:{code:200},data:[{accountId:'123',primaryEmailAddress:env.ZOHO_PRIMARY_EMAIL}]}:{status:{code:200},data:[]});};
 await createTransport(env,fetcher)({method:'GET',path:'/api/accounts/123/messages/view',query:{limit:10}});
 assert.equal(calls.length,3);assert.equal(calls[0].url,'https://accounts.zoho.com/oauth/v2/token');assert.ok(calls[0].body.includes('refresh_token=synthetic-refresh'));
 assert.ok(calls.every(c=>c.redirect==='manual'));assert.equal(calls[2].method,'GET');assert.equal(calls[2].headers.Authorization,'Zoho-oauthtoken synthetic-access');
});
test('safe diagnostics classify token refresh HTTP and allowlisted error without raw secrets',async()=>{
 const transport=createTransport(env,async()=>Response.json({error:'invalid_client',error_description:'SECRET_BODY',access_token:'SECRET_TOKEN'},{status:401}));
 try{await transport({method:'GET',path:'/api/accounts/123/messages/view',query:{}});assert.fail();}catch(error){const diagnostic=safeDiagnostic(error);assert.deepEqual(diagnostic,{stage:'token_refresh',httpStatus:401,reason:'provider_rejected',zohoCode:'invalid_client'});assert.ok(!JSON.stringify(diagnostic).includes('SECRET'));}
});
test('unknown provider error codes never reach diagnostics and account mismatch is specific',async()=>{
 const transport=createTransport(env,async()=>Response.json({error:'SECRET_UNKNOWN_CODE'},{status:400}));
 try{await transport({method:'GET',path:'/api/accounts/123/messages/view',query:{}});assert.fail();}catch(error){assert.ok(!JSON.stringify(safeDiagnostic(error)).includes('SECRET'));}
 let count=0;const mismatch=createTransport(env,async()=>Response.json(++count===1?{access_token:'test'}:{status:{code:200},data:[]}));
 try{await mismatch({method:'GET',path:'/api/accounts/123/messages/view',query:{}});assert.fail();}catch(error){assert.deepEqual(safeDiagnostic(error),{stage:'account_verification',httpStatus:200,reason:'account_mismatch'});}
});
test('network failure exposes fixed exception category and credential-free metadata probe status',async()=>{
 const calls=[];const transport=createTransport(env,async(url,init)=>{calls.push({url:String(url),init});if(calls.length===1)throw new TypeError('RAW_SECRET_ERROR');return Response.json({private:'NOT_RETURNED'});});
 try{await transport({method:'GET',path:'/api/accounts/123/messages/view',query:{}});assert.fail();}catch(error){const d=safeDiagnostic(error);assert.equal(d.exceptionClass,'TypeError');assert.equal(d.failureCategory,'network');assert.deepEqual(d.connectivity,{httpStatus:200});assert.ok(!JSON.stringify(d).includes('RAW_SECRET'));}
 assert.equal(calls[1].url,'https://accounts.zoho.com/oauth/serverinfo');assert.equal(calls[1].init.method,'GET');assert.ok(!calls[1].init.headers&&!calls[1].init.body);
});
test('account mismatch and host/path escape fail before mailbox retrieval',async()=>{
 let count=0; const fetcher=async()=>{count++;return Response.json(count===1?{access_token:'test'}:{status:{code:200},data:[{accountId:'999',primaryEmailAddress:env.ZOHO_PRIMARY_EMAIL}]});};
 await assert.rejects(createTransport(env,fetcher)({method:'GET',path:'/api/accounts/123/messages/view',query:{}})); assert.equal(count,2);
 count=0;await assert.rejects(createTransport(env,fetcher)({method:'GET',path:'https://evil.test',query:{}}));assert.equal(count,0);
});
