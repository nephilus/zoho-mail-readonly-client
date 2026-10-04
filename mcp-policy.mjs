// The host pin is trusted owner runtime configuration, never a tool argument.
// Requests match that one exact host, not a suffix/wildcard of other tenants.
export function approvedHost(config={}) {
 const host=config.mcpHost??'mcp.zoho.com';
 if(typeof host!=='string'||host!==host.toLowerCase()||!(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.zohomcp\.com$/.test(host)||host==='mcp.zoho.com'))throw Error('Invalid owner policy');
 return host;
}
export function mcpEndpoint(config){
 const url=new URL(config.mcpUrl);
 if(url.protocol!=='https:'||url.hostname!==approvedHost(config)||url.port||url.username||url.password||url.hash)throw Error('Endpoint denied');
 return url;
}
