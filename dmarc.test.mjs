import test from 'node:test';import assert from 'node:assert/strict';
import {gzipSync,zipSync,strToU8} from 'fflate';
import {parseDmarc,getDmarcReport,DMARC_LIMITS} from './dmarc.mjs';
const xml=`<?xml version="1.0" encoding="UTF-8"?><feedback><report_metadata><org_name>Example</org_name><report_id>report-1</report_id><date_range><begin>1700000000</begin><end>1700086400</end></date_range></report_metadata><policy_published><domain>example.test</domain><p>none</p></policy_published><record><row><source_ip>192.0.2.1</source_ip><count>12</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row></record><record><row><source_ip>2001:db8::1</source_ip><count>3</count><policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row></record></feedback>`;
test('plain XML, gzip and ZIP produce matching deterministic aggregates/dedup IDs',async()=>{
 const plain=await parseDmarc(strToU8(xml),'xml');assert.equal(plain.total,15);assert.equal(plain.aligned,12);assert.equal(plain.unaligned,3);assert.deepEqual(plain.disposition,{none:12,quarantine:0,reject:3});assert.equal(plain.sources[1].sourceIp,'2001:db8::1');assert.match(plain.dedupId,/^[a-f0-9]{64}$/);
 for(const [data,format] of [[gzipSync(strToU8(xml)),'gzip'],[zipSync({'report.xml':strToU8(xml)}),'zip']])assert.deepEqual(await parseDmarc(data,format),plain);
 const next=await parseDmarc(strToU8(xml.replace('report-1','report-2')),'xml');assert.notEqual(next.dedupId,plain.dedupId);
});
test('rejects DTD/XXE, custom entities, processing instructions and malformed XML without raw diagnostics',async()=>{
 for(const input of [xml.replace('<feedback>','<!DOCTYPE feedback [<!ENTITY secret SYSTEM "https://evil.test/secret">]><feedback>'),xml.replace('Example','&evil;'),xml.replace('<feedback>','<?fetch https://evil.test?><feedback>'),xml.replace('</feedback>','')])await assert.rejects(parseDmarc(strToU8(input),'xml'));
});
test('rejects domain mismatch, missing/duplicate fields, negative counts and invalid alignment',async()=>{
 for(const input of [xml.replace('example.test','other.test'),xml.replace('<count>12</count>',''),xml.replace('<count>12</count>','<count>12</count><count>12</count>'),xml.replace('<count>12</count>','<count>-12</count>'),xml.replace('<dkim>pass</dkim>','<dkim>unknown</dkim>')])await assert.rejects(parseDmarc(strToU8(input),'xml'));
});
test('bounded attachment and decompression reject oversize and gzip/ZIP bombs',async()=>{
 await assert.rejects(parseDmarc(new Uint8Array(DMARC_LIMITS.compressed+1),'xml'));
 const bomb=new Uint8Array(DMARC_LIMITS.expanded+10000).fill(32);
 for(const [data,format] of [[gzipSync(bomb),'gzip'],[zipSync({'report.xml':bomb}),'zip']])await assert.rejects(parseDmarc(data,format));
});
test('ZIP rejects traversal, nested archives, multiple files and truncated data',async()=>{
 for(const files of [{'../report.xml':strToU8(xml)},{'report.gz':gzipSync(strToU8(xml))},{'one.xml':strToU8(xml),'two.xml':strToU8(xml)}])await assert.rejects(parseDmarc(zipSync(files),'zip'));
 const zipped=zipSync({'report.xml':strToU8(xml)});await assert.rejects(parseDmarc(zipped.subarray(0,60),'zip'));
 await assert.rejects(parseDmarc(strToU8('not gzip'),'gzip'));
});
test('record/depth limits stop structurally excessive XML',async()=>{
 const record=xml.match(/<record>.*?<\/record>/)[0];const over=xml.replace(/<record>.*<\/record>/,record.repeat(DMARC_LIMITS.records+1));assert.ok(strToU8(over).length<DMARC_LIMITS.compressed);await assert.rejects(parseDmarc(strToU8(over),'xml'));
 await assert.rejects(parseDmarc(strToU8('<feedback>'+'<a>'.repeat(30)+'</a>'.repeat(30)+'</feedback>'),'xml'));
});
test('per-message report read uses pinned GET routes, skips unrelated files, deduplicates and hides hostile filenames/errors',async()=>{
 const calls=[];const transport=async op=>{calls.push(op);if(op.path.endsWith('attachmentinfo'))return {data:{attachments:[{attachmentId:'3',attachmentName:'first.xml',attachmentSize:xml.length},{attachmentId:'4',attachmentName:'again.gz',attachmentSize:xml.length},{attachmentId:'5',attachmentName:'SYNTHETIC_SECRET.txt',attachmentSize:10}]}};return op.path.endsWith('/3')?strToU8(xml):gzipSync(strToU8(xml));};
 const result=await getDmarcReport(transport,'1','2','9');assert.equal(result.reports.length,1);assert.equal(calls.length,3);assert.ok(calls.every(c=>c.method==='GET'&&c.path.startsWith('/api/accounts/1/folders/2/messages/9/')));assert.ok(!JSON.stringify(result).includes('SYNTHETIC_SECRET'));
});
test('same report ID with changed aggregates is flagged rather than silently deduplicated',async()=>{
 const transport=async op=>op.path.endsWith('attachmentinfo')?{data:{attachments:[{attachmentId:'3',attachmentName:'first.xml',attachmentSize:xml.length},{attachmentId:'4',attachmentName:'changed.xml',attachmentSize:xml.length}]}}:strToU8(op.path.endsWith('/3')?xml:xml.replace('<count>12</count>','<count>13</count>'));
 const result=await getDmarcReport(transport,'1','2','9');assert.equal(result.reports.length,1);assert.deepEqual(result.skipped,[{status:'conflicting_duplicate_report'}]);
});
