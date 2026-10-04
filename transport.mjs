import {boundedBytes,DMARC_LIMITS} from './dmarc.mjs';
const regions={us:['accounts.zoho.com','mail.zoho.com'],eu:['accounts.zoho.eu','mail.zoho.eu'],in:['accounts.zoho.in','mail.zoho.in'],au:['accounts.zoho.com.au','mail.zoho.com.au'],jp:['accounts.zoho.jp','mail.zoho.jp'],ca:['accounts.zohocloud.ca','mail.zohocloud.ca'],sa:['accounts.zoho.sa','mail.zoho.sa'],uk:['accounts.zoho.uk','mail.zoho.uk']};
const zohoCodes=new Set(['invalid_client','invalid_client_secret','invalid_code','invalid_grant','invalid_token','invalid_scope','access_denied','Access Denied','OAUTH_SCOPE_MISMATCH','INVALID_OAUTHTOKEN','AUTHENTICATION_FAILED','URL_RULE_NOT_CONFIGURED']);
class MailFailure extends Error{constructor(stage,httpStatus,reason,code){super('Mail unavailable');this.diagnostic={stage,...(Number.isInteger(httpStatus)&&httpStatus>=100&&httpStatus<=599?{httpStatus}:{}),reason,...(zohoCodes.has(code)?{zohoCode:code}:{})};}}
export function safeDiagnostic(error){return error instanceof MailFailure?error.diagnostic:{stage:'unknown',reason:'request_failed'};}
export function createTokenCache(now=Date.now){
 let current;
 return {async get(identity,load){
  if(!current||identity.some((value,i)=>value!==current.identity[i]))current={identity:[...identity],token:null,expiresAt:0,pending:null,error:null,retryAt:0};
  const entry=current;
  if(entry.token&&now()<entry.expiresAt)return entry.token;
  if(entry.error&&now()<entry.retryAt)throw entry.error;
  if(!entry.pending)entry.pending=(async()=>{
   try{const result=await load();if(typeof result.access_token!=='string'||!result.access_token||/[\r\n]/.test(result.access_token))throw new MailFailure('token_refresh',200,'missing_token');
    const seconds=Number(result.expires_in??3600);if(!Number.isFinite(seconds)||seconds<=60)throw new MailFailure('token_refresh',200,'invalid_expiry');
    entry.token=result.access_token;entry.expiresAt=now()+(Math.min(seconds,3600)-60)*1000;entry.error=null;return entry.token;
   }catch(error){entry.token=null;entry.error=error;entry.retryAt=now()+(safeDiagnostic(error).zohoCode==='Access Denied'?600000:60000);throw error;}
   finally{entry.pending=null;}
  })();
  return entry.pending;
 }};
}
const runtimeTokenCache=createTokenCache();
function fixedException(error){
 const exceptionClass=['TypeError','RangeError','AbortError','TimeoutError','Error'].includes(error?.name)?error.name:'Other';
 const failureCategory=['AbortError','TimeoutError'].includes(exceptionClass)?'timeout':error?.code==='ERR_INVALID_URL'?'invalid-url':exceptionClass==='TypeError'?'network':'other';
 return {exceptionClass,failureCategory};
}
export async function boundedText(stream,limit){
 if(!stream)return '';const reader=stream.getReader();const decoder=new TextDecoder();let size=0,text='';
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>limit)throw Error('Limit');text+=decoder.decode(value,{stream:true});}return text+decoder.decode();}finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
}
export function createTransport(env,fetcher=fetch,tokenCache=runtimeTokenCache){
 return async operation=>{
  const hosts=regions[env.ZOHO_REGION];const account=env.ZOHO_ACCOUNT_ID;
  if(!hosts||!/^\d{1,30}$/.test(account??'')||!env.ZOHO_PRIMARY_EMAIL||!env.ZOHO_CLIENT_ID||!env.ZOHO_CLIENT_SECRET||!env.ZOHO_REFRESH_TOKEN)throw Error('Setup');
  const allowed=new RegExp('^/api/accounts/'+account+'/(messages/(view|search)|folders/[0-9]{1,30}/messages/[0-9]{1,30}/content)$');
  const attachmentAllowed=env.DMARC_FOLDER_ID&&/^\d{1,30}$/.test(env.DMARC_FOLDER_ID)&&new RegExp('^/api/accounts/'+account+'/folders/'+env.DMARC_FOLDER_ID+'/messages/[0-9]{1,30}/(attachmentinfo|attachments/[0-9]{1,30})$').test(operation.path);
  if(operation.method!=='GET'||!allowed.test(operation.path)&&!attachmentAllowed||operation.binary&&(!attachmentAllowed||!/[\/]attachments[\/][0-9]+$/.test(operation.path)))throw Error('Invalid operation');
  const signal=AbortSignal.timeout(15000);
  const json=async(stage,url,init)=>{
   let response;try{response=await fetcher(url,{...init,redirect:'manual',signal});}catch(error){
    const failure=new MailFailure(stage,null,'request_failed');Object.assign(failure.diagnostic,fixedException(error));
    if(stage==='token_refresh'){
     try{const probe=await fetcher('https://accounts.zoho.com/oauth/serverinfo',{method:'GET',redirect:'manual',signal:AbortSignal.timeout(5000)});failure.diagnostic.connectivity={httpStatus:probe.status};await probe.body?.cancel();}
     catch(probeError){failure.diagnostic.connectivity=fixedException(probeError);}
    }
    throw failure;
   }
   if(response.status>=300&&response.status<400){await response.body?.cancel();throw new MailFailure(stage,response.status,'redirect_refused');}
   let text;try{text=await boundedText(response.body,1500000);}catch{throw new MailFailure(stage,response.status,'response_limit');}
   let result;try{result=JSON.parse(text);}catch{throw new MailFailure(stage,response.status,'invalid_json');}
   if(!response.ok||result.error||result.status&&result.status.code!==200)throw new MailFailure(stage,response.status,'provider_rejected',typeof result.error==='string'?result.error:result.data?.errorCode??result.error?.code);
   return result;
  };
  const accessToken=await tokenCache.get([env.ZOHO_REGION,env.ZOHO_CLIENT_ID,env.ZOHO_CLIENT_SECRET,env.ZOHO_REFRESH_TOKEN],()=>json('token_refresh','https://'+hosts[0]+'/oauth/v2/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'refresh_token',client_id:env.ZOHO_CLIENT_ID,client_secret:env.ZOHO_CLIENT_SECRET,refresh_token:env.ZOHO_REFRESH_TOKEN}).toString()}));
  const headers={Authorization:'Zoho-oauthtoken '+accessToken,Accept:'application/json'};
  const accounts=await json('account_verification','https://'+hosts[1]+'/api/accounts',{method:'GET',headers});
  if(!Array.isArray(accounts.data))throw new MailFailure('account_verification',200,'invalid_account_response');
  const match=accounts.data?.find(row=>row.accountId===account&&row.primaryEmailAddress?.toLowerCase()===env.ZOHO_PRIMARY_EMAIL.toLowerCase());
  if(!match)throw new MailFailure('account_verification',200,'account_mismatch');
  const url=new URL('https://'+hosts[1]+operation.path);for(const [key,value] of Object.entries(operation.query))url.searchParams.set(key,String(value));
  const stage=operation.path.endsWith('/attachmentinfo')?'dmarc_metadata':operation.path.endsWith('/view')?'list_messages':operation.path.endsWith('/search')?'search_messages':'get_message';
  if(operation.binary){
   let response;try{response=await fetcher(url,{method:'GET',headers:{...headers,Accept:'application/octet-stream'},redirect:'manual',signal});}catch{throw new MailFailure('attachment_read',null,'request_failed');}
   if(!response.ok){await response.body?.cancel();throw new MailFailure('attachment_read',response.status,response.status>=300&&response.status<400?'redirect_refused':'provider_rejected');}
   try{return await boundedBytes(response.body,DMARC_LIMITS.compressed);}catch{throw new MailFailure('attachment_read',response.status,'response_limit');}
  }
  return json(stage,url,{method:'GET',headers});
 };
}
