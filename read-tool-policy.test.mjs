import test from 'node:test';import assert from 'node:assert/strict';import {READ_TOOLS,canonicalReadTool,schemaAccepts} from './read-tool-policy.mjs';import {guardedFetch} from './local.mjs';
test('only explicitly observed aliases map to unchanged approved semantics',()=>{
 for(const [raw,canonical]of [['ZohoMail_getMailAccounts','getMailAccounts'],['ZohoMail_getAccountDetails','getAccountDetails'],['ZohoMail_listEmails','listEmails'],['ZohoMail_SearchEmails','SearchEmails'],['ZohoMail_getMessageContent','getMessageContent'],['ZohoMail_getMessageAttachmentInfo','getMessageAttachmentInfo']])assert.equal(canonicalReadTool(raw),canonical);
 for(const raw of ['ZohoMail_sendEmail','ZohoMail_deleteEmail','ZohoMail_readMessages','Other_listEmails','ZohoMail_listEmails_extra','zohomail_listEmails','ZohoMail_getMessageDetails','ZohoMail_getAllFolders'])assert.equal(canonicalReadTool(raw),null);
 assert.equal(READ_TOOLS.length,8);
});
test('nested runtime schema remains refused until field semantics are verified',()=>{
 const schema={type:'object',required:['path_variables','query_params'],properties:{path_variables:{type:'object',required:['accountId'],properties:{accountId:{type:'string'}}},query_params:{type:'object',required:['fields'],properties:{fields:{type:'string'},limit:{type:'integer'}}}}};
 assert.equal(schemaAccepts(schema,{path_variables:{accountId:'123'},query_params:{fields:'unverified',limit:1}}),false);
});
test('guard accepts exact observed read alias and rejects prefixed writes without transmission',async()=>{
 const config={mcpUrl:'https://mcp.zoho.com/synthetic'};let calls=0;const guarded=guardedFetch(config,async()=>{calls++;return Response.json({})});await guarded(config.mcpUrl,{method:'POST',body:JSON.stringify({method:'tools/call',params:{name:'ZohoMail_SearchEmails'}})});assert.equal(calls,1);
 await assert.rejects(guarded(config.mcpUrl,{method:'POST',body:JSON.stringify({method:'tools/call',params:{name:'ZohoMail_sendEmail'}})}));assert.equal(calls,1);
});
test('schema checks required own fields, exact primitive types, constraints and unsupported shapes',()=>{
 const schema={type:'object',required:['accountId','limit'],properties:{accountId:{type:'string'},limit:{type:'integer',minimum:1,maximum:50}}};assert(schemaAccepts(schema,{accountId:'123',limit:1}));for(const args of [{accountId:'123',limit:'1'},{accountId:'123',limit:51},{accountId:'123',limit:1,markRead:true}])assert(!schemaAccepts(schema,args));assert(!schemaAccepts({type:'object',required:['constructor'],properties:{}},{}));assert(!schemaAccepts({...schema,oneOf:[]},{accountId:'123',limit:1}));
});
