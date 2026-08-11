import { createHmac, timingSafeEqual } from 'node:crypto';
import { CAPTURE_ACTIONS, getPortalAccount } from './config.mjs';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NONCE_PATTERN = /^[0-9a-f-]{16,80}$/i;
const SENSITIVE_KEY = /(?:price|rate|amount|total|currency|availability|inventory|cookie|password|secret|token|authorization|credential|profile.?id|live.?url|cdp)/i;
const MAX_STRING_LENGTH = 4_000;

export class NonceStore {
  constructor(ttlMs = 300_000, maxEntries = 10_000) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.entries = new Map();
  }

  claim(nonce, nowMs = Date.now()) {
    for (const [key, expiresAt] of this.entries) {
      if (expiresAt <= nowMs) this.entries.delete(key);
    }
    if (this.entries.has(nonce)) return false;
    if (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest) this.entries.delete(oldest);
    }
    this.entries.set(nonce, nowMs + this.ttlMs);
    return true;
  }
}

function safeSignatureEqual(actual, expected) {
  if (!/^[0-9a-f]{64}$/i.test(actual || '')) return false;
  const left = Buffer.from(actual, 'hex');
  const right = Buffer.from(expected, 'hex');
  return left.length === right.length && timingSafeEqual(left, right);
}

export function verifySignedRequest({
  secret,
  timestamp,
  nonce,
  signature,
  body,
  nowMs = Date.now(),
  nonceStore,
}) {
  if (String(secret || '').length < 32) throw new Error('Signing configuration invalid');
  const seconds = Number(timestamp);
  if (!Number.isSafeInteger(seconds) || Math.abs(Math.floor(nowMs / 1000) - seconds) > 300) {
    throw new Error('Request timestamp expired');
  }
  if (!NONCE_PATTERN.test(String(nonce || ''))) throw new Error('Request nonce invalid');
  if (Buffer.byteLength(body || '', 'utf8') > 8_192) throw new Error('Request body too large');
  const expected = createHmac('sha256', secret)
    .update(`${timestamp}.${nonce}.${body}`)
    .digest('hex');
  if (!safeSignatureEqual(String(signature || ''), expected)) throw new Error('Request signature invalid');
  if (nonceStore && !nonceStore.claim(nonce, nowMs)) throw new Error('Request nonce replayed');

  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error('Request body invalid');
  }
  const keys = Object.keys(parsed || {}).sort();
  const expectedKeys = ['accountLabel', 'action', 'jobId', 'providerId'];
  if (JSON.stringify(keys) !== JSON.stringify(expectedKeys)) throw new Error('Request fields invalid');
  if (!UUID_PATTERN.test(String(parsed.jobId || ''))) throw new Error('Job id invalid');
  if (!CAPTURE_ACTIONS.has(parsed.action)) throw new Error('Action is not allowed');
  if (!getPortalAccount(parsed.providerId, parsed.accountLabel)) throw new Error('Account is not allowed');
  return Object.freeze({
    jobId: parsed.jobId,
    providerId: parsed.providerId,
    accountLabel: parsed.accountLabel,
    action: parsed.action,
  });
}

export function sanitizeCapturedValue(value, depth = 0) {
  if (depth > 8 || value == null) return value == null ? value : null;
  if (Array.isArray(value)) {
    return value.slice(0, 500).map((item) => sanitizeCapturedValue(item, depth + 1));
  }
  if (typeof value === 'object') {
    return Object.fromEntries(Object.entries(value)
      .filter(([key]) => !SENSITIVE_KEY.test(key))
      .map(([key, item]) => [key, sanitizeCapturedValue(item, depth + 1)]));
  }
  if (typeof value === 'string') return value.slice(0, MAX_STRING_LENGTH);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  return String(value).slice(0, MAX_STRING_LENGTH);
}

export function sanitizeRunnerError(error) {
  const code = typeof error === 'object' && error ? String(error.code || '') : '';
  const messages = {
    session_expired: 'Portal session expired',
    account_mismatch: 'Exact portal account could not be verified',
    list_route_unverified: 'Portal order-list route is not verified',
    capture_empty: 'Portal capture returned no order rows',
    duplicate_capture_failed: 'Repeated capture was not idempotent',
    browser_unavailable: 'Portal browser is unavailable',
    job_not_claimed: 'Portal job is no longer available',
  };
  return messages[code] || 'Portal capture failed';
}

export function safeRequestErrorCode(error) {
  const message = String(error?.message || '');
  if (/signature/i.test(message)) return 'invalid_signature';
  if (/timestamp/i.test(message)) return 'expired_timestamp';
  if (/nonce replay/i.test(message)) return 'nonce_replay';
  if (/cannot be claimed|no longer available/i.test(message)) return 'job_conflict';
  if (/account/i.test(message)) return 'account_not_allowed';
  if (/action/i.test(message)) return 'action_not_allowed';
  if (/body too large/i.test(message)) return 'body_too_large';
  return 'invalid_request';
}
