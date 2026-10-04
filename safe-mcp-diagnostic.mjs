import {contentTypeCategory} from './initialize-summary.mjs';
export const TRANSPORT_STAGES=Object.freeze(['initialize','initialized_notification','tool_inventory','tool_call','session_stream','session_close']);
export function endpointPattern(endpoint){const path=endpoint.pathname.split('/').filter(Boolean);return path.length===3&&path[0]==='mcp'&&path[2]==='message'?'mcp_key_message':path.length===2&&path[0]==='mcp'?'mcp_key':'other';}
const errorCodes=new Set(['INVALID_TOKEN','INVALID_OAUTHTOKEN','INVALID_CLIENT','OAUTH_SCOPE_MISMATCH','INVALID_SCOPE','INVALID_OAUTH_SCOPE','INVALID_REFRESH_TOKEN','RATE_LIMIT_EXCEEDED','TOO_MANY_REQUESTS','invalid_scope','invalid_token','invalid_request','invalid_client','invalid_grant','access_denied','rate_limit_exceeded','too_many_requests',-32700,-32600,-32601,-32602,-32603]);
export function transportStage(method,rpc){return method==='GET'?'session_stream':method==='DELETE'?'session_close':({initialize:'initialize','notifications/initialized':'initialized_notification','tools/list':'tool_inventory','tools/call':'tool_call'}[rpc?.method]??null);}
export function retryDelay(value,now=Date.now()){
 if(typeof value!=='string'||value.length>80)return null;
 if(/^\d{1,5}$/.test(value)){const n=Number(value);return n<=86400?n:null;}
 if(!/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(value))return null;
 const date=Date.parse(value),seconds=Math.ceil((date-now)/1000);return Number.isFinite(date)&&seconds>=0&&seconds<=86400?seconds:null;
}
function knownCode(value,depth=0){
 if(depth>5||!value||typeof value!=='object')return null;
 for(const key of ['code','error','errorCode','error_code'])if(errorCodes.has(value[key]))return value[key];
 for(const key of ['error','status','data']){const code=knownCode(value[key],depth+1);if(code!==null)return code;}
 return null;
}
export async function httpDiagnostic(response,stage){
 const diagnostic={transportStage:stage,httpStatus:response.status,contentType:contentTypeCategory(response),retryAfterSeconds:retryDelay(response.headers.get('retry-after')),errorCode:null};
 const reader=response.body?.getReader();if(!reader)return diagnostic;
 let timer;const timed=new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('bounded')),2000)});
 try{
  const chunks=[];let bytes=0;
  while(true){const item=await Promise.race([reader.read(),timed]);if(item.done)break;bytes+=item.value.byteLength;if(bytes>8192)return diagnostic;chunks.push(item.value);}
  const all=new Uint8Array(bytes);let offset=0;for(const chunk of chunks){all.set(chunk,offset);offset+=chunk.byteLength;}
  if(diagnostic.contentType==='application/json')try{diagnostic.errorCode=knownCode(JSON.parse(new TextDecoder().decode(all)))}catch{}
 }catch{}finally{clearTimeout(timer);void reader.cancel().catch(()=>{});}
 return diagnostic;
}
export function networkDiagnostic(stage,error){return {transportStage:stage,httpStatus:null,contentType:'missing',retryAfterSeconds:null,errorCode:null,networkCategory:['AbortError','TimeoutError'].includes(error?.name)?'timeout':'network_error'};}
export function toolDiagnostic(result){
 let errorCode=knownCode(result?.structuredContent);
 for(const item of (result?.content??[]).slice(0,10))if(errorCode===null&&item.type==='text'&&typeof item.text==='string'&&item.text.length<=8192)try{errorCode=knownCode(JSON.parse(item.text))}catch{}
 return {transportStage:'tool_call',httpStatus:null,contentType:'missing',retryAfterSeconds:null,errorCode};
}
