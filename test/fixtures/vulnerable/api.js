'use strict';
/*
 * FIXTURE — intentionally insecure. See index.html in this directory.
 *
 * Reproduces the SSRF shape found in the free-tools Lambda: a network target
 * taken from an unauthenticated query string with no containment at all.
 */

const net = require('net');
const http = require('http');
const https = require('https');

// CODE-05: CORS falls open to "*" when the env var is unset
function corsHeaders() {
  return { 'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGIN || '*' };
}

// CODE-04: no IP-literal rejection, no guarded lookup, no scheme allow-list
function checkPort(host, port) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    socket.on('connect', () => { socket.destroy(); resolve({ open: true }); });
    socket.on('error', e => resolve({ open: false, reason: e.code }));
    socket.connect(port, host);
  });
}

function proxy(targetUrl) {
  return new Promise(resolve => {
    const parsed = new URL(targetUrl);
    const lib = parsed.protocol === 'http:' ? http : https;
    // CODE-15: verification disabled on an ordinary request
    const req = lib.request(parsed, { rejectUnauthorized: false }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.end();
  });
}

async function handler(event) {
  const params = event.queryStringParameters || {};
  if (params.tool === 'port') return { headers: corsHeaders(), body: JSON.stringify(await checkPort(params.host, Number(params.port))) };
  if (params.tool === 'proxy') return { headers: corsHeaders(), body: JSON.stringify(await proxy(params.url)) };
  return { statusCode: 400, headers: corsHeaders(), body: '{}' };
}

module.exports = { handler };
