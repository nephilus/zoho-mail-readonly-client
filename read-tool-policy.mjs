export const READ_TOOLS=Object.freeze(['getMailAccounts','getAccountDetails','listEmails','SearchEmails','getMessageContent','getMessageAttachmentInfo','getAllFolders','getFolder']);
// These exact names were observed in the owner's runtime inventory.
// No generic prefix stripping, case folding, or new read semantics.
const aliases=Object.freeze({ZohoMail_getMailAccounts:'getMailAccounts',ZohoMail_getAccountDetails:'getAccountDetails',ZohoMail_listEmails:'listEmails',ZohoMail_SearchEmails:'SearchEmails',ZohoMail_getMessageContent:'getMessageContent',ZohoMail_getMessageAttachmentInfo:'getMessageAttachmentInfo'});
export function canonicalReadTool(name){return typeof name==='string'?(READ_TOOLS.includes(name)?name:Object.hasOwn(aliases,name)?aliases[name]:null):null;}
export function schemaAccepts(schema,args,depth=0){
 if(depth>3)return false;
 if(schema?.type!=='object'||schema.$ref||schema.oneOf||schema.anyOf||schema.allOf||!Array.isArray(schema.required??[])||!args||Array.isArray(args)||typeof args!=='object')return false;
 if((schema.required??[]).some(key=>!Object.hasOwn(args,key)))return false;
 for(const [key,value]of Object.entries(args)){
  const spec=schema.properties?.[key];if(!spec||spec.$ref||spec.oneOf||spec.anyOf||spec.allOf)return false;
  const valid=spec.type==='object'?schemaAccepts(spec,value,depth+1):spec.type==='string'?typeof value==='string':spec.type==='integer'?Number.isInteger(value):spec.type==='number'?typeof value==='number'&&Number.isFinite(value):spec.type==='boolean'?typeof value==='boolean':false;
  if(!valid)return false;
  if(typeof value==='number'&&((spec.minimum??-Infinity)>value||(spec.maximum??Infinity)<value))return false;
  if(typeof value==='string'&&((spec.minLength??0)>value.length||(spec.maxLength??Infinity)<value.length))return false;
  if(spec.pattern)return false;
  if(spec.format&&(spec.format!=='int32'||spec.type!=='integer'||value< -2147483648||value>2147483647))return false;
  if(spec.enum&&(!Array.isArray(spec.enum)||!spec.enum.includes(value)))return false;
 }return true;
}
// Canonical callers supply flat arguments. Only observed Zoho wrappers are mapped.
export function mappedReadArgs(tool,values){
 const schema=tool?.inputSchema;if(!schema||!values||Array.isArray(values)||typeof values!=='object')return null;
 if(!schema.properties?.path_variables)return schemaAccepts(schema,values)?values:null;
 const name=canonicalReadTool(tool.name);
 const paths={getAccountDetails:['accountId'],listEmails:['accountId'],SearchEmails:['accountId'],getMessageContent:['accountId','folderId','messageId']}[name];
 if(!paths||!tool.name.startsWith('ZohoMail_'))return null;
 const queryKeys={getAccountDetails:[],listEmails:['limit','start','folderId'],SearchEmails:['limit','start','searchKey'],getMessageContent:['includeBlockContent']}[name];
 if(Object.keys(values).some(k=>!paths.includes(k)&&!queryKeys.includes(k)))return null;
 const args={path_variables:Object.fromEntries(paths.filter(k=>Object.hasOwn(values,k)).map(k=>[k,values[k]]))};
 const query=Object.fromEntries(queryKeys.filter(k=>Object.hasOwn(values,k)).map(k=>[k,values[k]]));
 if(name==='listEmails'||name==='SearchEmails'){
  query.limit??=1;query.start??=1;
  if(!Number.isInteger(query.limit)||query.limit<1||query.limit>50||!Number.isInteger(query.start)||query.start<1)return null;
 }
 // Runtime schema explicitly documents messageId as an allowed field selection.
 if(name==='listEmails')query.fields='messageId';
 if(Object.keys(query).length)args.query_params=query;
 return schemaAccepts(schema,args)?args:null;
}
