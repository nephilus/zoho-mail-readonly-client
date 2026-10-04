import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {boundedBytes,getDmarcReport} from './dmarc.mjs';
import {createTransport,safeDiagnostic} from './transport.mjs';
import {mcpEndpoint} from './mcp-policy.mjs';

export const READ_TOOLS=Object.freeze(['getMailAccounts','getAccountDetails','listEmails','SearchEmails','getMessageContent','getMessageAttachmentInfo','getAllFolders','getFolder']);

class LocalFailure extends Error{constructor(reason){super('Local Zoho request unavailable');this.reason=reason;}}
function refuse(reason){throw new LocalFailure(reason);}
export function safeLocalError(e){return {ok:false,status:e instanceof LocalFailure?e.reason:e?.name==='UnauthorizedError'?'mcp_authorization_required':['AbortError','TimeoutError'].includes(e?.name)?'timeout':'request_failed'};}
export function endpoint(value,mcpHost){try{return mcpEndpoint({mcpUrl:value,mcpHost});}catch{refuse('invalid_endpoint');}}
function secretValues(config){const values=[config.mcpUrl,config.mcpBearerToken,config.rest?.ZOHO_CLIENT_ID,config.rest?.ZOHO_CLIENT_SECRET,config.rest?.ZOHO_REFRESH_TOKEN];if(config.mcpUrl){const url=endpoint(config.mcpUrl,config.mcpHost);for(const v of url.searchParams.values())values.push(v);for(const p of url.pathname.split('/'))if(p.length>20)values.push(p);}return [...new Set(values.filter(v=>typeof v==='string'&&v.length>3).flatMap(v=>[v,encodeURIComponent(v)]))].sort((a,b)=>b.length-a.length);}
export function sanitize(value,config){
 const secrets=secretValues(config);const redact=text=>secrets.reduce((s,k)=>s.split(k).join('[REDACTED]'),text);
 const walk=(v,depth=0)=>{if(depth>15)return '[DEPTH LIMIT]';if(typeof v==='string')return redact(v).slice(0,50000);if(Array.isArray(v))return v.slice(0,50).map(x=>walk(x,depth+1));if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).slice(0,100).filter(([k])=>!/(token|secret|authorization|api.?key|password|credential)/i.test(k)).map(([k,x])=>[redact(k),walk(x,depth+1)]));return v;};
 const result=walk(value);if(JSON.stringify(result).length>100000)refuse('result_limit');return result;
}
export function guardedFetch(config,fetcher=fetch){
 const expected=endpoint(config.mcpUrl,config.mcpHost);
 return async(input,init={})=>{
  let url;try{url=new URL(input instanceof Request?input.url:String(input));}catch{refuse('endpoint_denied');}
  if(url.href!==expected.href||!['GET','POST','DELETE'].includes(init.method??'GET'))refuse('endpoint_denied');
  if(init.method==='POST'){
   let rpc;try{rpc=JSON.parse(init.body);}catch{refuse('protocol_denied');}
   if(!['initialize','notifications/initialized','tools/list','tools/call'].includes(rpc.method))refuse('protocol_denied');
   if(rpc.method==='tools/call'&&!READ_TOOLS.includes(rpc.params?.name))refuse('tool_denied');
  }
  const signal=AbortSignal.any([AbortSignal.timeout(30000),...(init.signal?[init.signal]:[])]);
  const response=await fetcher(url,{...init,redirect:'manual',signal});
  if(response.status===401||response.status===403){await response.body?.cancel();refuse('mcp_authorization_required');}
  if(response.status>=300&&response.status<400){await response.body?.cancel();refuse('redirect_denied');}
  if(!response.ok&&response.status!==405){await response.body?.cancel();refuse('provider_rejected');}
  // A streaming cap applies before the SDK parses JSON/SSE, including long streams.
  let size=0;const stream=response.body?.pipeThrough(new TransformStream({transform(chunk,controller){size+=chunk.byteLength;if(size>1500000)refuse('response_limit');controller.enqueue(chunk);}}));
  return new Response(stream,{status:response.status,headers:response.headers});
 };
}
function contents(result){if(result?.isError)refuse('provider_tool_error');return (result?.content??[]).filter(c=>c.type==='text').map(c=>{try{return JSON.parse(c.text);}catch{return c.text;}});}
function findAccount(value,accountId,primaryEmail){if(Array.isArray(value))return value.some(v=>findAccount(v,accountId,primaryEmail));if(value&&typeof value==='object'){if(String(value.accountId??'')===accountId&&value.primaryEmailAddress?.toLowerCase()===primaryEmail.toLowerCase())return true;return Object.values(value).some(v=>findAccount(v,accountId,primaryEmail));}return false;}
export async function execute(config,request,{fetcher=fetch,clientFactory=()=>new Client({name:'zoho-local-readonly',version:'0.1.0'},{capabilities:{},autoFulfill:false})}={}){
 if(!request||typeof request!=='object')refuse('invalid_request');
 if(request.action!=='list_tools'&&(!/^\d{1,30}$/.test(config.accountId??'')||typeof config.primaryEmail!=='string'||config.primaryEmail.length>320||!config.primaryEmail.includes('@')))refuse('account_setup_required');
 if(request.action==='dmarc'){
  if(!/^\d{1,30}$/.test(request.messageId??'')||Object.keys(request).some(k=>!['action','messageId'].includes(k)))refuse('invalid_arguments');
  if(!/^\d{1,30}$/.test(config.dmarcFolderId??'')||! /^[a-z0-9.-]{1,253}$/.test(config.dmarcDomain??''))refuse('dmarc_setup_required');
  const rest={...config.rest,ZOHO_ACCOUNT_ID:config.accountId,ZOHO_REGION:'us',ZOHO_PRIMARY_EMAIL:config.primaryEmail,DMARC_FOLDER_ID:config.dmarcFolderId};
  const result=await getDmarcReport(createTransport(rest,fetcher),rest.ZOHO_ACCOUNT_ID,config.dmarcFolderId,request.messageId,config.dmarcDomain);
  // Preserve up to 1000 bounded report rows; ordinary MCP output has a smaller cap.
  return {ok:true,result};
 }
 if(!['list_tools','call'].includes(request.action))refuse('unsupported_action');
 if(request.action==='call'&&!READ_TOOLS.includes(request.name))refuse('tool_denied');
 endpoint(config.mcpUrl,config.mcpHost);const client=clientFactory();const transport=new StreamableHTTPClientTransport(endpoint(config.mcpUrl,config.mcpHost),{fetch:guardedFetch(config,fetcher),requestInit:config.mcpBearerToken?{headers:{Authorization:'Bearer '+config.mcpBearerToken}}:{}});
 try{
  await client.connect(transport);const discovery=await client.listTools();
  if(discovery.tools.length>100)refuse('tool_count_limit');
  // Fail closed if the configured provider server has any write/unknown tool.
  if(discovery.tools.some(t=>!READ_TOOLS.includes(t.name)||t.annotations?.readOnlyHint===false||t.annotations?.destructiveHint===true))refuse('server_not_readonly');
  if(request.action==='list_tools')return {ok:true,tools:sanitize(discovery.tools.map(t=>({name:t.name,inputSchema:t.inputSchema})),config)};
  if(!discovery.tools.some(t=>t.name===request.name))refuse('tool_unavailable');
  const account=config.accountId;if(!/^\d{1,30}$/.test(account??''))refuse('account_setup_required');
  const args=request.arguments??{};if(!args||Array.isArray(args)||typeof args!=='object'||JSON.stringify(args).length>8192)refuse('invalid_arguments');
  for(const [key,value] of Object.entries(args)){if(/account.?id/i.test(key)&&String(value)!==account)refuse('account_denied');if(/^(limit|count|page.?size)$/i.test(key)&&(!Number.isInteger(value)||value<1||value>50))refuse('paging_denied');if(/(mark.?read|read.?status|update|delete|send)/i.test(key))refuse('argument_denied');}
  if(!discovery.tools.some(t=>t.name==='getMailAccounts'))refuse('account_verification_unavailable');
  const accounts=contents(await client.callTool({name:'getMailAccounts',arguments:{}}));if(!findAccount(accounts,account,config.primaryEmail))refuse('account_response_unverified');
  if(request.name==='getMailAccounts')return {ok:true,result:{accountId:account,primaryEmailAddress:config.primaryEmail}};
  // Require the pinned account explicitly for account-scoped tool calls.
  if(!Object.entries(args).some(([k,v])=>/^accountId$/i.test(k)&&String(v)===account))refuse('account_argument_required');
  return {ok:true,result:sanitize(contents(await client.callTool({name:request.name,arguments:args})),config)};
 }finally{await client.close().catch(()=>{});}
}
export function restDiagnostic(e){return {ok:false,status:'rest_unavailable',diagnostic:safeDiagnostic(e)};}
