import {execute,safeLocalError,restDiagnostic} from './local.mjs';
// User-run ephemeral setup/probe only. No files, shell history, argv or secret echo.
export async function hidden(prompt,input=process.stdin,output=process.stderr){
 if(!input.isTTY||!output.isTTY)throw Error('Interactive terminal required');
 output.write(prompt);input.setRawMode(true);input.resume();
 return new Promise((resolve,reject)=>{let value='';const done=(error)=>{input.off('data',onData);input.setRawMode(false);input.pause();output.write('\n');error?reject(Error('Input cancelled')):resolve(value);};
 const onData=chunk=>{for(const char of chunk.toString('utf8')){if(char==='\u0003'){done(true);return;}if(char==='\r'||char==='\n'){done(false);return;}if(char==='\u007f'||char==='\b')value=value.slice(0,-1);else if(char>=' '&&char<='~')value+=char;if(value.length>16000){done(true);return;}}};input.on('data',onData);
 });
}
let request;
try{
 request=JSON.parse(await hidden('Read-only request JSON (hidden): '));
 const config=JSON.parse(await hidden('Account/domain/folder policy JSON, no credentials (hidden): '));
 if(request.action==='dmarc')config.rest={ZOHO_CLIENT_ID:await hidden('REST client ID (hidden): '),ZOHO_CLIENT_SECRET:await hidden('REST client secret (hidden): '),ZOHO_REFRESH_TOKEN:await hidden('REST refresh token (hidden): ')};
 else {config.mcpUrl=await hidden('Official MCP endpoint URL (hidden): ');config.mcpBearerToken=await hidden('Previously authorized MCP access token, if required; blank otherwise (hidden): ');}
 process.stdout.write(JSON.stringify(await execute(config,request))+'\n');
}catch(e){process.stdout.write(JSON.stringify(request?.action==='dmarc'?restDiagnostic(e):safeLocalError(e))+'\n');process.exitCode=1;}
