import sax from 'sax';
import {Unzip,UnzipInflate} from 'fflate';

export const DMARC_LIMITS=Object.freeze({compressed:512000,expanded:2000000,records:1000,nodes:30000,depth:20,attachments:3});
class ReportFailure extends Error{constructor(reason){super('Report unavailable');this.reason=reason;}}
function fail(reason){throw new ReportFailure(reason);}
export function reportDiagnostic(error){return error instanceof ReportFailure?error.reason:'invalid_report';}
export async function boundedBytes(stream,limit){
 const reader=stream?.getReader();if(!reader)fail('empty_attachment');const chunks=[];let size=0;
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>limit)fail('size_limit');chunks.push(value);}const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}return bytes;}
 finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
}
async function unpack(bytes,format){
 if(!(bytes instanceof Uint8Array)||!bytes.length)fail('empty_attachment');if(bytes.length>DMARC_LIMITS.compressed)fail('size_limit');
 if(format==='xml')return bytes;
 if(format==='gzip'){
  if(bytes[0]!==31||bytes[1]!==139)fail('invalid_archive');
  try{return await boundedBytes(new Response(bytes).body.pipeThrough(new DecompressionStream('gzip')),DMARC_LIMITS.expanded);}catch(e){if(e instanceof ReportFailure)throw e;fail('invalid_archive');}
 }
 if(format!=='zip'||bytes[0]!==80||bytes[1]!==75)fail('invalid_archive');
 let files=0,complete=false,total=0;const chunks=[];
 try{
  const unzip=new Unzip(file=>{
   if(++files>1||!file.name||file.name.length>200||/[\\/:]/.test(file.name)||file.name.includes('..')||!file.name.toLowerCase().endsWith('.xml'))fail('unsupported_archive');
   if(![0,8].includes(file.compression)||file.originalSize>DMARC_LIMITS.expanded)fail('unsupported_archive');
   file.ondata=(error,chunk,final)=>{if(error)fail('invalid_archive');total+=chunk.length;if(total>DMARC_LIMITS.expanded)fail('size_limit');chunks.push(chunk);if(final)complete=true;};file.start();
  });unzip.register(UnzipInflate);
  // Small compressed chunks bound each inflation step before the output callback.
  for(let i=0;i<bytes.length;i+=128)unzip.push(bytes.subarray(i,Math.min(i+128,bytes.length)),i+128>=bytes.length);
 }catch(e){if(e instanceof ReportFailure)throw e;fail('invalid_archive');}
 if(files!==1||!complete)fail('invalid_archive');const result=new Uint8Array(total);let offset=0;for(const c of chunks){result.set(c,offset);offset+=c.length;}return result;
}
function one(node,name){const rows=node.children.filter(c=>c.name===name);if(rows.length!==1)fail('invalid_schema');return rows[0];}
function text(node,name){const child=one(node,name);if(child.children.length)fail('invalid_schema');return child.text.trim();}
function number(value,max=Number.MAX_SAFE_INTEGER){if(!/^\d{1,16}$/.test(value))fail('invalid_schema');const n=Number(value);if(!Number.isSafeInteger(n)||n>max)fail('invalid_schema');return n;}
function choice(value,values){if(!values.includes(value))fail('invalid_schema');return value;}
export async function parseDmarc(bytes,format,domain='example.test'){
 const expanded=await unpack(bytes,format);if(expanded.length>DMARC_LIMITS.expanded)fail('size_limit');
 let xml;try{xml=new TextDecoder('utf-8',{fatal:true}).decode(expanded);}catch{fail('invalid_encoding');}
 // Prohibit declarations before parser buffering, including DTD/internal subsets.
 if(/<!\s*(DOCTYPE|ENTITY)\b/i.test(xml))fail('unsafe_xml');
 const parser=sax.parser(true,{strictEntities:true,xmlns:true,position:false});let root,nodes=0,records=0;const stack=[];
 parser.onerror=()=>fail('invalid_xml');parser.ondoctype=()=>fail('unsafe_xml');parser.onsgmldeclaration=()=>fail('unsafe_xml');
 parser.onprocessinginstruction=pi=>{if(pi.name!=='xml')fail('unsafe_xml');};
 parser.onopentag=tag=>{
  if(++nodes>DMARC_LIMITS.nodes||stack.length>=DMARC_LIMITS.depth||tag.name.length>80||Object.keys(tag.attributes).length>8)fail('structure_limit');
  if(tag.local==='record'&&++records>DMARC_LIMITS.records)fail('record_limit');
  const node={name:tag.local,text:'',children:[]};if(stack.length)stack.at(-1).children.push(node);else {if(root)fail('invalid_schema');root=node;}stack.push(node);
 };
 parser.ontext=parser.oncdata=value=>{if(stack.length&&value.trim()){const node=stack.at(-1);node.text+=value;if(node.text.length>1024)fail('field_limit');}else if(value.trim())fail('invalid_xml');};
 parser.onclosetag=()=>stack.pop();
 try{for(let i=0;i<xml.length;i+=4096)parser.write(xml.slice(i,i+4096));parser.close();}catch(e){if(e instanceof ReportFailure)throw e;fail('invalid_xml');}
 if(!root||root.name!=='feedback'||stack.length)fail('invalid_schema');
 const metadata=one(root,'report_metadata'),policy=one(root,'policy_published'),dates=one(metadata,'date_range');
 const reportDomain=text(policy,'domain').toLowerCase();if(reportDomain!==domain)fail('domain_mismatch');
 const reportId=text(metadata,'report_id'),organization=text(metadata,'org_name');if(!reportId||reportId.length>200||!organization||organization.length>200)fail('invalid_schema');
 const begin=number(text(dates,'begin'),4102444800),end=number(text(dates,'end'),4102444800);if(end<begin)fail('invalid_schema');
 const publishedPolicy=choice(text(policy,'p'),['none','quarantine','reject']);
 const rows=root.children.filter(c=>c.name==='record');if(!rows.length)fail('invalid_schema');
 const sources=[];let total=0,aligned=0;const disposition={none:0,quarantine:0,reject:0};
 for(const row of rows){
  const r=one(row,'row'),evaluation=one(r,'policy_evaluated'),ip=text(r,'source_ip');if(!/^[0-9a-f:.]{3,64}$/i.test(ip)||!/[.:]/.test(ip))fail('invalid_schema');
  const count=number(text(r,'count'),1000000000);if(count<1)fail('invalid_schema');
  const dkim=choice(text(evaluation,'dkim'),['pass','fail']),spf=choice(text(evaluation,'spf'),['pass','fail']),action=choice(text(evaluation,'disposition'),['none','quarantine','reject']);
  total+=count;if(!Number.isSafeInteger(total))fail('invalid_schema');if(dkim==='pass'||spf==='pass')aligned+=count;disposition[action]+=count;
  sources.push({sourceIp:ip,count,dkimAlignment:dkim,spfAlignment:spf,disposition:action});
 }
 const hash=async value=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(value)))),b=>b.toString(16).padStart(2,'0')).join('');
 const dedupId=await hash([reportDomain,organization,reportId,begin,end]);
 const contentFingerprint=await hash([publishedPolicy,total,aligned,disposition,sources]);
 return {domain:reportDomain,organization,reportId,dedupId,contentFingerprint,begin,end,publishedPolicy,total,aligned,unaligned:total-aligned,disposition,sources};
}
export async function getDmarcReport(transport,accountId,folderId,messageId,domain){
 const root=`/api/accounts/${accountId}/folders/${folderId}/messages/${messageId}`;
 const metadata=await transport({method:'GET',path:root+'/attachmentinfo',query:{includeInline:false}});
 const attachments=metadata?.data?.attachments;if(!Array.isArray(attachments)||attachments.length>DMARC_LIMITS.attachments)fail('attachment_limit');
 const reports=[],skipped=[];
 for(const attachment of attachments){
  const name=typeof attachment.attachmentName==='string'?attachment.attachmentName.toLowerCase():'';
  const format=name.endsWith('.xml.gz')||name.endsWith('.gz')?'gzip':name.endsWith('.xml')?'xml':name.endsWith('.zip')?'zip':null;
  if(!format){skipped.push({status:'unsupported_type'});continue;}
  if(!/^\d{1,30}$/.test(attachment.attachmentId??'')||!Number.isSafeInteger(attachment.attachmentSize)||attachment.attachmentSize<1||attachment.attachmentSize>DMARC_LIMITS.compressed){skipped.push({status:'size_or_metadata_limit'});continue;}
  const bytes=await transport({method:'GET',path:root+'/attachments/'+attachment.attachmentId,query:{},binary:true});
  try{const report=await parseDmarc(bytes,format,domain);const prior=reports.find(r=>r.dedupId===report.dedupId);if(!prior)reports.push(report);else if(prior.contentFingerprint!==report.contentFingerprint)skipped.push({status:'conflicting_duplicate_report'});}catch(e){skipped.push({status:reportDiagnostic(e)});}
 }
 return {messageId,reports,skipped,note:'Untrusted report data; alignment failures do not by themselves prove malicious sending. No report retention or cross-message deduplication.'};
}
