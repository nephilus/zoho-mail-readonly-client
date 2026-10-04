// Parse a bounded initialize response, returning fixed categories only.
// Server names, messages, headers, URLs, session IDs and arbitrary data never leave this module.
export function contentTypeCategory(response){
 const type=(response.headers.get('content-type')??'').split(';')[0].trim().toLowerCase();
 return ['application/json','text/event-stream','text/html','text/plain'].includes(type)?type:type?'other':'missing';
}
function classify(message){
 if(message?.jsonrpc!=='2.0'||message.id!==1)return null;
 if(message.error){const codes=new Map([[-32700,'parse_error'],[-32600,'invalid_request'],[-32601,'method_not_found'],[-32602,'invalid_params'],[-32603,'internal_error']]);return {ok:false,status:'jsonrpc_error',mcpCategory:codes.get(message.error.code)??'provider_error'};}
 if(typeof message.result?.protocolVersion==='string'&&message.result.capabilities&&typeof message.result.capabilities==='object'){
  const versions=['2024-11-05','2025-03-26','2025-06-18','2025-11-25','2026-07-28'];
  return {ok:true,status:'mcp_initialized',mcpCategory:'initialize_result',protocolVersion:versions.includes(message.result.protocolVersion)?message.result.protocolVersion:'other',toolsAdvertised:!!message.result.capabilities.tools};
 }return {ok:false,status:'protocol_response_unrecognized',mcpCategory:'invalid_initialize_result'};
}
export async function summarizeInitialization(response){
 const summary={httpStatus:response.status,contentType:contentTypeCategory(response)};
 if(response.status>=300&&response.status<400){await response.body?.cancel();return {...summary,ok:false,status:'redirect_denied'};}
 if(response.status===202||response.status===204){await response.body?.cancel();return {...summary,ok:false,status:'initialize_result_missing'};}
 if(!['application/json','text/event-stream'].includes(summary.contentType)){await response.body?.cancel();return {...summary,ok:false,status:response.ok?'unexpected_content_type':'provider_http_error'};}
 const reader=response.body?.getReader();if(!reader)return {...summary,ok:false,status:'initialize_result_missing'};
 let bytes=0,text='';const decoder=new TextDecoder('utf-8',{fatal:true});
 try{
  for(;;){const {value,done}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>65536)return {...summary,ok:false,status:'response_limit'};text+=decoder.decode(value,{stream:true});
   if(summary.contentType==='text/event-stream'){
    for(;;){const boundary=/\r?\n\r?\n/.exec(text);if(!boundary)break;const frame=text.slice(0,boundary.index);text=text.slice(boundary.index+boundary[0].length);const data=frame.split(/\r?\n/).filter(line=>line.startsWith('data:')).map(line=>line.slice(5).replace(/^ /,'')).join('\n');if(!data)continue;
     const messages=JSON.parse(data);for(const message of Array.isArray(messages)?messages:[messages]){const result=classify(message);if(result)return {...summary,...result};}
    }
   }
  }
  text+=decoder.decode();
  if(summary.contentType==='application/json'){const messages=JSON.parse(text);for(const message of Array.isArray(messages)?messages:[messages]){const result=classify(message);if(result)return {...summary,...result};}}
  return {...summary,ok:false,status:response.ok?'protocol_response_unrecognized':'provider_http_error'};
 }catch{return {...summary,ok:false,status:'protocol_response_unrecognized'};}
 finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
}
