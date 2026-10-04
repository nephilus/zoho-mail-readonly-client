import {execute,safeLocalError,restDiagnostic} from './local.mjs';
// Exactly one private JSON envelope on stdin, never secrets in argv/environment/files.
let text='';let request;
try{
 for await(const chunk of process.stdin){text+=chunk.toString('utf8');if(text.length>65536)throw Error();}
 const envelope=JSON.parse(text);request=envelope.request;const result=await execute(envelope.config??{},request);text='';process.stdout.write(JSON.stringify(result)+'\n');
}catch(e){text='';process.stdout.write(JSON.stringify(request?.action==='dmarc'?restDiagnostic(e):safeLocalError(e))+'\n');process.exitCode=1;}
