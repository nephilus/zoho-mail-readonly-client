// Read-only discovery. Never registration, authorization, token exchange or mail tools.
import {approvedHost,mcpEndpoint} from './mcp-policy.mjs';
import {contentTypeCategory,summarizeInitialization} from './initialize-summary.mjs';
function checked(value,allowed) { const u=new URL(value); if(u.protocol!=='https:'||!allowed.has(u.hostname)||u.port||u.username||u.password||u.hash)throw Error(); return u; }
async function getJSON(url,fetcher,allowed) {
 const r=await fetcher(checked(url,allowed),{redirect:'manual',signal:AbortSignal.timeout(15000)});
 if(!r.ok)throw Error(); let bytes=0,text='';for await(const chunk of r.body){bytes+=chunk.length;if(bytes>65536)throw Error();text+=new TextDecoder().decode(chunk,{stream:true});}return JSON.parse(text);
}
export async function inspect(config,fetcher=fetch) {
 const endpoint=mcpEndpoint(config);const allowed=new Set([approvedHost(config),'mcp.zoho.com','accounts.zoho.com']);
 const r=await fetcher(endpoint,{method:'POST',redirect:'manual',signal:AbortSignal.timeout(15000),headers:{'Content-Type':'application/json',Accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'readonly-auth-inspector',version:'0.1.0'}}})});
 const status=r.status;const challenge=r.headers.get('www-authenticate')??'';
 if(status!==401&&status!==403)return summarizeInitialization(r);
 const transportSummary={httpStatus:status,contentType:contentTypeCategory(r)};await r.body?.cancel();
 const match=/\bresource_metadata="([^"]+)"/.exec(challenge);
 if(!match)return {...transportSummary,ok:false,status:'resource_metadata_not_advertised'};
 const resourceURL=checked(match[1],allowed);if(resourceURL.hostname!==endpoint.hostname)return {ok:false,status:'metadata_origin_review_required'};
 const resource=await getJSON(resourceURL,fetcher,allowed);
 if(resource.resource!==endpoint.href||!Array.isArray(resource.authorization_servers)||resource.authorization_servers.length!==1)return {ok:false,status:'resource_binding_unverified'};
 const issuer=checked(resource.authorization_servers[0],allowed);
 const metadataURL=new URL('/.well-known/oauth-authorization-server'+issuer.pathname.replace(/\/$/,''),issuer.origin);
 const metadata=await getJSON(metadataURL,fetcher,allowed);
 if(metadata.issuer!==issuer.href)return {ok:false,status:'issuer_mismatch'};
 for(const key of ['authorization_endpoint','token_endpoint','registration_endpoint'])if(metadata[key])checked(metadata[key],allowed);
 return {...transportSummary,ok:true,status:'metadata_inspected',authorizationCode:metadata.grant_types_supported?.includes('authorization_code')===true,refresh:metadata.grant_types_supported?.includes('refresh_token')===true,pkceS256:metadata.code_challenge_methods_supported?.includes('S256')===true,dynamicRegistrationAdvertised:typeof metadata.registration_endpoint==='string',loopbackRedirect:'requires_registration_review',consentScopes:'requires_owner_review'};
}
if(process.argv[1]?.endsWith('inspect-auth.mjs')){
 try {let input='';for await(const chunk of process.stdin){input+=chunk.toString();if(input.length>65536)throw Error();}const config=JSON.parse(input);input='';console.log(JSON.stringify(await inspect(config)));}
 catch {console.log(JSON.stringify({ok:false,status:'discovery_unavailable'}));process.exitCode=1;}
}
