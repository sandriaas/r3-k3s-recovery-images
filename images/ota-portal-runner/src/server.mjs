import { createServer } from 'node:http';
import { getPortalAccount, loadConfig } from './config.mjs';
import { D1Client } from './d1.mjs';
import { PortalJobRunner } from './jobs.mjs';
import { NonceStore, safeRequestErrorCode, verifySignedRequest } from './security.mjs';

const config = loadConfig();
const d1 = new D1Client(config);
const runner = new PortalJobRunner(config, d1);
const nonceStore = new NonceStore();
const requestBuckets = new Map();

const server = createServer(async (request, response) => {
  setSecurityHeaders(response);
  if (request.method === 'GET' && request.url === '/healthz') {
    return json(response, 200, { ok: true, service: 'ota-portal-runner' });
  }
  if (request.method !== 'POST' || !['/', '/jobs'].includes(request.url || '')) {
    return json(response, 404, { ok: false });
  }
  if (!claimRateLimit(request.socket.remoteAddress || 'unknown')) {
    return json(response, 429, { ok: false, error: 'rate_limited' });
  }
  try {
    const body = await readBody(request);
    const nonce = String(request.headers['x-ota-nonce'] || '');
    const job = verifySignedRequest({
      secret: config.signingSecret,
      timestamp: String(request.headers['x-ota-timestamp'] || ''),
      nonce,
      signature: String(request.headers['x-ota-signature'] || ''),
      body,
      nonceStore,
    });
    if (!getPortalAccount(job.providerId, job.accountLabel)) {
      return json(response, 403, { ok: false });
    }
    await runner.claimAndStart(job, nonce);
    safeLog({
      event: 'request_accepted',
      jobId: job.jobId,
      providerId: job.providerId,
      accountLabel: job.accountLabel,
      action: job.action,
    });
    return json(response, 202, { ok: true, jobId: job.jobId });
  } catch (error) {
    const code = safeRequestErrorCode(error);
    safeLog({ event: 'request_rejected', code });
    const status = code === 'job_conflict' ? 409 : 401;
    return json(response, status, { ok: false });
  }
});

server.listen(config.port, '0.0.0.0', () => {
  process.stdout.write(`${JSON.stringify({
    event: 'runner_started',
    port: config.port,
    accountCount: 8,
  })}\n`);
  void runner.startNextQueuedJob();
});

function setSecurityHeaders(response) {
  response.setHeader('content-type', 'application/json; charset=utf-8');
  response.setHeader('cache-control', 'no-store');
  response.setHeader('x-content-type-options', 'nosniff');
  response.setHeader('content-security-policy', "default-src 'none'");
}

function json(response, status, body) {
  response.statusCode = status;
  response.end(JSON.stringify(body));
}

function safeLog(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

async function readBody(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > 8_192) throw new Error('Request body too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function claimRateLimit(identity, now = Date.now()) {
  const windowStart = now - 60_000;
  const recent = (requestBuckets.get(identity) || []).filter((item) => item >= windowStart);
  if (recent.length >= 60) {
    requestBuckets.set(identity, recent);
    return false;
  }
  requestBuckets.set(identity, [...recent, now]);
  if (requestBuckets.size > 1_000) {
    for (const [key, timestamps] of requestBuckets) {
      if (timestamps.every((item) => item < windowStart)) requestBuckets.delete(key);
    }
  }
  return true;
}
