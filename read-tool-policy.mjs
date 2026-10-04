export const READ_TOOLS=Object.freeze(['getMailAccounts','getAccountDetails','listEmails','SearchEmails','getMessageContent','getMessageAttachmentInfo','getAllFolders','getFolder']);
// These exact names were observed in the owner's runtime inventory.
// No generic prefix stripping, case folding, or new read semantics.
const aliases=Object.freeze({ZohoMail_getMailAccounts:'getMailAccounts',ZohoMail_getAccountDetails:'getAccountDetails',ZohoMail_listEmails:'listEmails',ZohoMail_SearchEmails:'SearchEmails',ZohoMail_getMessageContent:'getMessageContent',ZohoMail_getMessageAttachmentInfo:'getMessageAttachmentInfo'});
export function canonicalReadTool(name){return typeof name==='string'?(READ_TOOLS.includes(name)?name:Object.hasOwn(aliases,name)?aliases[name]:null):null;}
export function schemaAccepts(schema,args){
 if(schema?.type!=='object'||schema.$ref||schema.oneOf||schema.anyOf||schema.allOf||!Array.isArray(schema.required??[])||!args||Array.isArray(args)||typeof args!=='object')return false;
 if((schema.required??[]).some(key=>!Object.hasOwn(args,key)))return false;
 for(const [key,value]of Object.entries(args)){
  const spec=schema.properties?.[key];if(!spec||spec.$ref||spec.oneOf||spec.anyOf||spec.allOf)return false;
  const valid=spec.type==='string'?typeof value==='string':spec.type==='integer'?Number.isInteger(value):spec.type==='number'?typeof value==='number'&&Number.isFinite(value):spec.type==='boolean'?typeof value==='boolean':false;
  if(!valid)return false;
  if(typeof value==='number'&&((spec.minimum??-Infinity)>value||(spec.maximum??Infinity)<value))return false;
  if(typeof value==='string'&&((spec.minLength??0)>value.length||(spec.maxLength??Infinity)<value.length))return false;
  if(spec.pattern||spec.format)return false; // Do not invent support for provider-specific validation.
  if(spec.enum&&(!Array.isArray(spec.enum)||!spec.enum.includes(value)))return false;
 }return true;
}
