import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {guardedFetch,sanitize,safeLocalError} from './local.mjs';
import {canonicalReadTool,schemaAccepts} from './read-tool-policy.mjs';
import {mcpEndpoint} from './mcp-policy.mjs';

const statusError=status=>Object.assign(Error('Read check stopped'),{safeStatus:status});
function schemaArgs(tool,values){
 const schema=tool?.inputSchema;if(schema?.type!=='object'||!Array.isArray(schema.required??[])||(schema.required??[]).some(key=>!Object.hasOwn(values,key)))return null;
 const args={};for(const [key,value]of Object.entries(values)){const spec=schema.properties?.[key];if(!spec)continue;if(spec.type!==(typeof value==='number'?'integer':'string'))return null;if(typeof value==='number'&&((spec.minimum??-Infinity)>value||(spec.maximum??Infinity)<value))return null;args[key]=value;}
 if(!schemaAccepts(schema,args))return null;return args;
}
function decoded(result){
 if(result?.isError)throw statusError('provider_tool_error');
 if(result.structuredContent&&typeof result.structuredContent==='object')return [result.structuredContent];
 const content=result?.content??[];if(content.length>10)throw statusError('tool_result_shape_unverified');
 return content.filter(c=>c.type==='text').map(c=>{if(c.text.length>200000)throw statusError('tool_result_shape_unverified');try{return JSON.parse(c.text)}catch{throw statusError('tool_result_shape_unverified')}});
}
function ownerAccount(values,email){
 const matches=new Set();let visited=0;
 const walk=(value,depth=0)=>{if(depth>15||++visited>5000)throw statusError('account_response_unverified');if(Array.isArray(value)){for(const child of value)walk(child,depth+1)}else if(value&&typeof value==='object'){if(typeof value.primaryEmailAddress==='string'&&value.primaryEmailAddress.toLowerCase()===email.toLowerCase()&&typeof value.accountId==='string'&&/^\d{1,30}$/.test(value.accountId))matches.add(value.accountId);for(const child of Object.values(value))walk(child,depth+1)}};
 walk(values);if(matches.size!==1)throw statusError('owner_binding_unverified');return [...matches][0];
}
function safeName(name,config){
 const value=sanitize(String(name),config);const endpoint=mcpEndpoint(config);const path=endpoint.pathname.split('/');const index=path.indexOf('mcp');const keys=[...endpoint.searchParams.values(),...(index>=0&&path[index+1]?[path[index+1]]:[])];
 if(keys.some(key=>key&&[key,encodeURIComponent(key),decodeURIComponent(key)].some(secret=>value.includes(secret))))return '[REDACTED TOOL NAME]';
 return /^[A-Za-z][A-Za-z0-9_.:-]{0,80}$/.test(value)&&!/[0-9]{10,}/.test(value)?value:'[REDACTED TOOL NAME]';
}
function schemaStatus(tool,config){
 if(tool.inputSchema?.type!=='object')return 'unsupported';
 if(canonicalReadTool(tool.name)==='getMailAccounts')return schemaArgs(tool,{})?'compatible':'unsupported';
 if(canonicalReadTool(tool.name)==='listEmails'){
  const props=tool.inputSchema.properties??{};if(props.accountId?.type!=='string'||props.limit?.type!=='integer')return 'unsupported';
  const values={accountId:'0',limit:1};if(props.start)values.start=1;if(props.folderId&&config.folderId)values.folderId=config.folderId;
  return schemaArgs(tool,values)?'compatible':'unsupported';
 }return 'not_used';
}
export async function ownerReadCheck(config,{fetcher=fetch,clientFactory=()=>new Client({name:'owner-readonly-check',version:'0.1.0'},{capabilities:{},autoFulfill:false})}={}){
 const summary={ok:false,status:'check_unavailable',tools:[],ownerMatched:false,messageCount:null};let client;
 try{
  mcpEndpoint(config);if(typeof config.primaryEmail!=='string'||!config.primaryEmail.includes('@')||config.primaryEmail.length>320)throw statusError('owner_binding_required');
  client=clientFactory();await client.connect(new StreamableHTTPClientTransport(mcpEndpoint(config),{fetch:guardedFetch(config,fetcher)}));
  const tools=[];let cursor;const seen=new Set();
  for(let page=0;page<5;page++){
   const response=await client.listTools(cursor?{cursor}:undefined);tools.push(...response.tools);if(tools.length>100)throw statusError('tool_count_limit');cursor=response.nextCursor;if(!cursor)break;if(seen.has(cursor))throw statusError('tool_inventory_incomplete');seen.add(cursor);
  }if(cursor)throw statusError('tool_inventory_incomplete');
  const names=new Set();let denied=false;
  for(const tool of tools){const canonical=canonicalReadTool(tool.name);const allowed=!!canonical&&tool.annotations?.readOnlyHint!==false&&tool.annotations?.destructiveHint!==true;if(canonical&&names.has(canonical))denied=true;names.add(canonical??tool.name);if(!allowed)denied=true;summary.tools.push({name:safeName(tool.name,config),allowed,schema:schemaStatus(tool,config)});}
  if(denied)throw statusError('server_not_readonly');
  const accounts=tools.find(t=>canonicalReadTool(t.name)==='getMailAccounts'),list=tools.find(t=>canonicalReadTool(t.name)==='listEmails');
  if(!accounts||!list)throw statusError('required_tool_unavailable');
  const accountArgs=schemaArgs(accounts,{});if(!accountArgs)throw statusError('account_schema_unsupported');
  const props=list.inputSchema?.properties??{};
  if(props.accountId?.type!=='string'||props.limit?.type!=='integer')throw statusError('list_schema_unsupported');
  const owner=ownerAccount(decoded(await client.callTool({name:accounts.name,arguments:accountArgs})),config.primaryEmail);summary.ownerMatched=true;
  const values={accountId:owner,limit:1};if(props.start)values.start=1;
  if(props.folderId&&config.folderId&&/^\d{1,30}$/.test(config.folderId))values.folderId=config.folderId;
  const args=schemaArgs(list,values);if(!args||args.accountId!==owner||args.limit!==1)throw statusError('list_schema_unsupported');
  const parts=decoded(await client.callTool({name:list.name,arguments:args}));if(parts.length!==1)throw statusError('tool_result_shape_unverified');
  const payload=parts[0];if(payload?.status?.code&&payload.status.code!==200)throw statusError('provider_tool_error');
  const rows=Array.isArray(payload)?payload:payload?.data;if(!Array.isArray(rows)||rows.length>1)throw statusError('message_bound_unverified');
  summary.messageCount=rows.length;summary.ok=true;summary.status='read_verified';return summary;
 }catch(error){summary.status=error.safeStatus??safeLocalError(error).status;return summary;}
 finally{await client?.close().catch(()=>{});}
}
if(process.argv[1]?.endsWith('owner-read-check.mjs')){
 try{let input='';for await(const chunk of process.stdin){input+=chunk.toString();if(input.length>65536)throw Error();}const config=JSON.parse(input);input='';console.log(JSON.stringify(await ownerReadCheck(config)));}
 catch{console.log(JSON.stringify({ok:false,status:'check_unavailable',tools:[],ownerMatched:false,messageCount:null}));process.exitCode=1;}
}
