import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {guardedFetch,sanitize,safeLocalError} from './local.mjs';
import {mcpEndpoint} from './mcp-policy.mjs';
import {canonicalReadTool,mappedReadArgs,schemaAccepts} from './read-tool-policy.mjs';
import {toolDiagnostic} from './safe-mcp-diagnostic.mjs';
const fail=(status,diagnostic)=>{throw Object.assign(Error('Review stopped'),{safeStatus:status,safeDiagnostic:diagnostic});};
const id=value=>typeof value==='string'&&/^\d{1,30}$/.test(value);
function decoded(result){
 if(result?.isError)fail('provider_tool_error',toolDiagnostic(result));
 if(result?.structuredContent&&typeof result.structuredContent==='object')return result.structuredContent;
 const text=(result?.content??[]).filter(c=>c.type==='text');if(text.length!==1||text[0].text.length>200000)fail('response_shape_unverified');
 try{return JSON.parse(text[0].text)}catch{fail('response_shape_unverified')}
}
function payload(value){for(let n=0;n<3;n++){if(value?.status?.code&&value.status.code!==200)fail('provider_tool_error');if(value?.data&&!Array.isArray(value.data)&&typeof value.data==='object'&&Object.hasOwn(value.data,'data'))value=value.data;else return value;}fail('response_shape_unverified');}
function owner(value,email){const matches=new Set();let nodes=0;function walk(v,depth=0){if(++nodes>5000||depth>15)fail('owner_response_unverified');if(Array.isArray(v))v.forEach(x=>walk(x,depth+1));else if(v&&typeof v==='object'){if(id(v.accountId)&&typeof v.primaryEmailAddress==='string'&&v.primaryEmailAddress.toLowerCase()===email.toLowerCase())matches.add(v.accountId);Object.values(v).forEach(x=>walk(x,depth+1));}}walk(value);if(matches.size!==1)fail('owner_binding_unverified');return [...matches][0];}
export function reviewText(value){return String(value??'').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,' ').replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi,' ').replace(/<[^>]*>/g,' ').replace(/https?:\/\/\S+/gi,'[link omitted]').replace(/(?:password|api.?key|access.?token|verification.?code|one.?time.?code)\s*[:=][^\n]*/gi,'[sensitive detail omitted]').replace(/\s+/g,' ').trim().slice(0,4000);}
export function itCandidate(subject){return /\b(?:IT|VPN|backup|restore|ransomware|phishing|malware|security|server|network|firewall|outage|incident|certificate|domain|DNS|Microsoft 365|Office 365|login|sign.in|account lock|access request|support ticket)\b/i.test(subject??'');}
export async function reviewRecentCatchall(config,{fetcher=fetch,clientFactory=()=>new Client({name:'zoho-private-review',version:'0.1.0'},{capabilities:{},autoFulfill:false})}={}){
 const output={ok:false,status:'review_unavailable',ownerMatched:false,coverage:{folder:'catchall',pages:0,listed:0,unique:0,contentRead:0,maxMessages:10,maxContent:3,morePossible:false,repliesChecked:false,historyComplete:false},candidates:[]};let client;
 try{
  mcpEndpoint(config);if(!id(config.catchallFolderId)||typeof config.primaryEmail!=='string'||!config.primaryEmail.includes('@'))fail('review_binding_required');
  client=clientFactory();await client.connect(new StreamableHTTPClientTransport(mcpEndpoint(config),{fetch:guardedFetch(config,fetcher)}));
  const tools=[];let cursor;const seenCursors=new Set();for(let page=0;page<5;page++){const response=await client.listTools(cursor?{cursor}:undefined);tools.push(...response.tools);if(tools.length>100)fail('tool_inventory_unverified');cursor=response.nextCursor;if(!cursor)break;if(seenCursors.has(cursor))fail('tool_inventory_unverified');seenCursors.add(cursor);}if(cursor)fail('tool_inventory_unverified');
  const names=tools.map(t=>canonicalReadTool(t.name));if(names.some(n=>!n)||new Set(names).size!==names.length||tools.some(t=>t.annotations?.readOnlyHint===false||t.annotations?.destructiveHint===true))fail('server_not_readonly');
  const accounts=tools.find(t=>canonicalReadTool(t.name)==='getMailAccounts'),list=tools.find(t=>canonicalReadTool(t.name)==='listEmails'),content=tools.find(t=>canonicalReadTool(t.name)==='getMessageContent');
  if(!accounts||!list||!schemaAccepts(accounts.inputSchema,{}))fail('required_tool_unavailable');
  const account=owner(decoded(await client.callTool({name:accounts.name,arguments:{}})),config.primaryEmail);output.ownerMatched=true;
  const rows=new Map();
  for(let page=0;page<2;page++){
   const args=mappedReadArgs(list,{accountId:account,folderId:config.catchallFolderId,limit:5,start:1+page*5});if(!args?.query_params)fail('list_schema_unsupported');
   args.query_params.fields='messageId,subject,fromAddress,toAddress,receivedTime,folderId,threadId,status';if(!schemaAccepts(list.inputSchema,args))fail('list_schema_unsupported');
   const mail=payload(decoded(await client.callTool({name:list.name,arguments:args}))),data=mail?.data;
   if(!Array.isArray(data)||data.length>5)fail('page_bound_unverified');output.coverage.pages++;output.coverage.listed+=data.length;output.coverage.morePossible=data.length===5;
   for(const row of data){if(!id(row.messageId)||String(row.folderId)!==config.catchallFolderId)fail('message_binding_unverified');if(!rows.has(row.messageId))rows.set(row.messageId,row);}
   if(data.length<5)break;
  }
  output.coverage.unique=rows.size;
  for(const row of rows.values()){
   if(!itCandidate(row.subject))continue;
   const candidate={subject:String(row.subject??'').slice(0,300),from:String(row.fromAddress??'').slice(0,320),receivedTime:/^\d{10,16}$/.test(String(row.receivedTime??''))?String(row.receivedTime):null,assessment:'IT-related candidate; resolution not verified'};
   if(content&&output.coverage.contentRead<3){const args=mappedReadArgs(content,{accountId:account,folderId:config.catchallFolderId,messageId:row.messageId,includeBlockContent:false});if(!args)fail('content_schema_unsupported');const mail=payload(decoded(await client.callTool({name:content.name,arguments:args})));candidate.reviewExcerpt=reviewText(mail?.data?.content);output.coverage.contentRead++;}
   output.candidates.push(candidate);
  }
  output.ok=true;output.status='bounded_review_complete';return sanitize(output,config);
 }catch(error){const safe=safeLocalError(error);output.status=error.safeStatus??safe.status;const diagnostic=error.safeDiagnostic??safe.diagnostic;if(diagnostic)output.transportDiagnostic=diagnostic;return sanitize(output,config);}
 finally{await client?.close().catch(()=>{});}
}
if(process.argv[1]?.endsWith('mail-review.mjs')){try{let input='';for await(const chunk of process.stdin){input+=chunk.toString();if(input.length>65536)throw Error();}const config=JSON.parse(input);input='';console.log(JSON.stringify(await reviewRecentCatchall(config)));}catch{console.log(JSON.stringify({ok:false,status:'review_unavailable'}));process.exitCode=1;}}
