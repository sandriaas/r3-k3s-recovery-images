import { randomUUID } from 'node:crypto';
import { decryptSecret, encryptSecret } from './crypto.mjs';

const nowIso = () => new Date().toISOString();

export class D1Client {
  constructor(config) {
    this.url = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(config.cloudflareAccountId)}/d1/database/${encodeURIComponent(config.d1DatabaseId)}/query`;
    this.token = config.cloudflareApiToken;
    this.scrapeCredKey = config.scrapeCredKey;
  }

  async request(statementOrBatch) {
    const response = await fetch(this.url, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${this.token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(statementOrBatch),
      signal: AbortSignal.timeout(30_000),
    });
    const body = await response.json().catch(() => null);
    const result = Array.isArray(body?.result) ? body.result : [];
    if (!response.ok || body?.success !== true || result.some((item) => item?.success === false)) {
      throw new Error('D1 request failed');
    }
    return result;
  }

  async query(sql, params = []) {
    const result = await this.request({ sql, params });
    return Array.isArray(result[0]?.results) ? result[0].results : [];
  }

  async execute(sql, params = []) {
    const result = await this.request({ sql, params });
    return Number(result[0]?.meta?.changes || 0);
  }

  async batch(statements) {
    if (statements.length === 0) return [];
    return this.request({ batch: statements });
  }

  async claimJob(jobId, runnerRequestId) {
    const timestamp = nowIso();
    const changes = await this.execute(
      `UPDATE ota_portal_capture_jobs
       SET status='running', runner_request_id=?, started_at=COALESCE(started_at, ?),
           attempts=attempts+1, sanitized_error=NULL, updated_at=?
       WHERE id=? AND status='queued' AND runner_request_id IS NULL`,
      [runnerRequestId, timestamp, timestamp, jobId],
    );
    if (changes !== 1) {
      const error = new Error('Job cannot be claimed');
      error.code = 'job_not_claimed';
      throw error;
    }
  }

  async nextQueuedJob() {
    const rows = await this.query(
      `SELECT id, provider_id, account_label, action
       FROM ota_portal_capture_jobs
       WHERE status='queued' AND runner_request_id IS NULL
       ORDER BY requested_at, id
       LIMIT 1`,
    );
    const row = rows[0];
    return row ? Object.freeze({
      jobId: String(row.id),
      providerId: String(row.provider_id),
      accountLabel: String(row.account_label),
      action: String(row.action),
    }) : null;
  }

  async setLiveLogin(jobId, liveUrl, expiresAt) {
    const encrypted = await encryptSecret(liveUrl, this.scrapeCredKey);
    await this.execute(
      `UPDATE ota_portal_capture_jobs
       SET live_login_url_enc=?, live_login_url_iv=?, live_login_expires_at=?, updated_at=?
       WHERE id=? AND status='running'`,
      [encrypted.secretEnc, encrypted.iv, expiresAt, nowIso(), jobId],
    );
  }

  async finishJob(jobId, {
    status,
    orderCount = 0,
    eventCount = 0,
    detailCount = 0,
    sanitizedError = null,
  }) {
    const timestamp = nowIso();
    await this.execute(
      `UPDATE ota_portal_capture_jobs
       SET status=?, result_order_count=?, result_event_count=?, result_detail_count=?,
           sanitized_error=?, finished_at=?, live_login_url_enc=NULL,
           live_login_url_iv=NULL, live_login_expires_at=NULL, updated_at=?
       WHERE id=? AND status='running'`,
      [status, orderCount, eventCount, detailCount, sanitizedError, timestamp, timestamp, jobId],
    );
  }

  async ensureAccount(providerId, accountLabel) {
    const id = `${providerId}-${accountLabel}`;
    const timestamp = nowIso();
    await this.execute(
      `INSERT OR IGNORE INTO crawl_accounts
       (id, provider_id, label, status, profile_status, created_by, created_at, updated_at)
       VALUES (?, ?, ?, 'unconfigured', 'unconfigured', 'ota-portal-runner', ?, ?)`,
      [id, providerId, accountLabel, timestamp, timestamp],
    );
    const rows = await this.query(
      `SELECT id, provider_id, label, username, cookie_enc, iv, source_url, status,
              browser_profile_id_enc, browser_profile_iv, profile_status
       FROM crawl_accounts WHERE provider_id=? AND label=? LIMIT 1`,
      [providerId, accountLabel],
    );
    if (!rows[0]) throw new Error('Portal account could not be loaded');
    return rows[0];
  }

  async getAccountSecrets(providerId, accountLabel) {
    const row = await this.ensureAccount(providerId, accountLabel);
    const cookies = row.cookie_enc && row.iv
      ? await decryptSecret(row.cookie_enc, row.iv, this.scrapeCredKey).catch(() => null)
      : null;
    const profileId = row.browser_profile_id_enc && row.browser_profile_iv
      ? await decryptSecret(row.browser_profile_id_enc, row.browser_profile_iv, this.scrapeCredKey).catch(() => null)
      : null;
    return Object.freeze({
      id: row.id,
      username: row.username || null,
      sourceUrl: row.source_url || null,
      cookies,
      profileId,
      status: row.status || 'unconfigured',
      profileStatus: row.profile_status || 'unconfigured',
    });
  }

  async saveProfile(providerId, accountLabel, profileId, profileStatus = 'active') {
    const encrypted = await encryptSecret(profileId, this.scrapeCredKey);
    const timestamp = nowIso();
    await this.execute(
      `UPDATE crawl_accounts
       SET browser_profile_id_enc=?, browser_profile_iv=?, profile_status=?,
           profile_updated_at=?, updated_at=?
       WHERE provider_id=? AND label=?`,
      [encrypted.secretEnc, encrypted.iv, profileStatus, timestamp, timestamp, providerId, accountLabel],
    );
  }

  async markAccount(providerId, accountLabel, {
    status,
    profileStatus,
    verified = false,
  }) {
    const timestamp = nowIso();
    await this.execute(
      `UPDATE crawl_accounts
       SET status=?, profile_status=?,
           last_login_at=CASE WHEN ? THEN ? ELSE last_login_at END,
           profile_last_verified_at=CASE WHEN ? THEN ? ELSE profile_last_verified_at END,
           profile_updated_at=?, updated_at=?
       WHERE provider_id=? AND label=?`,
      [
        status,
        profileStatus,
        verified ? 1 : 0,
        timestamp,
        verified ? 1 : 0,
        timestamp,
        timestamp,
        timestamp,
        providerId,
        accountLabel,
      ],
    );
  }

  async priorOrderReferences(providerId, accountLabel, limit = 100) {
    const rows = await this.query(
      `SELECT order_ref FROM portal_orders
       WHERE provider_id=? AND COALESCE(account_label, 'default')=?
       ORDER BY captured_at DESC LIMIT ?`,
      [providerId, accountLabel, limit],
    );
    return new Set(rows.map((row) => String(row.order_ref || '')).filter(Boolean));
  }

  async classifierEvidence(providerId, accountLabel) {
    const rows = await this.query(
      `SELECT capability_status, supported_event_types_json, evidence_json
       FROM ota_portal_recipe_bindings
       WHERE provider_id=? AND account_label=? AND purpose='event_classifier' LIMIT 1`,
      [providerId, accountLabel],
    );
    const row = rows[0];
    if (!row || row.capability_status !== 'verified') {
      return Object.freeze({ verified: false, supported: [], cancelledStatuses: [] });
    }
    const supported = parseJsonArray(row.supported_event_types_json);
    const evidence = parseJsonObject(row.evidence_json);
    return Object.freeze({
      verified: true,
      supported,
      cancelledStatuses: Array.isArray(evidence.cancelledStatuses)
        ? evidence.cancelledStatuses.map((item) => normalizeText(item)).filter(Boolean)
        : [],
    });
  }

  async captureCapabilities(providerId, accountLabel) {
    const rows = await this.query(
      `SELECT purpose, capability_status, supported_event_types_json, evidence_json
       FROM ota_portal_recipe_bindings
       WHERE provider_id=? AND account_label=?`,
      [providerId, accountLabel],
    );
    return new Map(rows.map((row) => [String(row.purpose), Object.freeze({
      status: String(row.capability_status || 'missing'),
      supportedEventTypes: parseJsonArray(row.supported_event_types_json),
      evidence: parseJsonObject(row.evidence_json),
    })]));
  }

  async savePortalRows(providerId, accountLabel, rows) {
    const bootstrapRows = await this.query(
      `SELECT 1 AS present FROM ota_portal_event_bootstrap
       WHERE provider_id=? AND account_label=? LIMIT 1`,
      [providerId, accountLabel],
    );
    const hasBaseline = bootstrapRows.length > 0;
    const classifier = await this.classifierEvidence(providerId, accountLabel);
    let eventCount = 0;
    for (const row of rows) {
      const created = await this.savePortalRow(providerId, accountLabel, row, hasBaseline, classifier);
      if (created) eventCount += 1;
    }
    return Object.freeze({ orderCount: rows.length, eventCount });
  }

  async savePortalRow(providerId, accountLabel, snapshot, hasBaseline, classifier) {
    const existingRows = await this.query(
      `SELECT id, order_ref, customer_name, pickup_location, dropoff_location,
              pickup_datetime, dropoff_datetime, vehicle, status, reference
       FROM portal_orders
       WHERE provider_id=? AND COALESCE(account_label, 'default')=? AND order_ref=?
       LIMIT 1`,
      [providerId, accountLabel, snapshot.orderRef],
    );
    const existing = existingRows[0] || null;
    const previous = existing ? snapshotFromRow(existing) : null;
    const currentFingerprint = portalSnapshotFingerprint(snapshot);
    const previousFingerprint = previous ? portalSnapshotFingerprint(previous) : null;
    const changedFields = previous ? changedSnapshotFields(previous, snapshot) : [];
    const eventType = classifyPortalSnapshotEvent({
      previous,
      snapshot,
      hasBaseline,
      classifier,
      changedFields,
      previousFingerprint,
      currentFingerprint,
    });
    const timestamp = nowIso();
    const portalOrderId = existing?.id || randomUUID();

    const snapshotStatement = !existing
      ? {
        sql: `INSERT INTO portal_orders
         (id, provider_id, account_label, order_ref, customer_name, pickup_location,
          dropoff_location, pickup_datetime, dropoff_datetime, vehicle, status,
          reference, raw_json, captured_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        params: [
          portalOrderId,
          providerId,
          accountLabel,
          snapshot.orderRef,
          snapshot.customerName,
          snapshot.pickupLocation,
          snapshot.dropoffLocation,
          snapshot.pickupDatetime,
          snapshot.dropoffDatetime,
          snapshot.vehicle,
          snapshot.status,
          snapshot.reference,
          JSON.stringify(snapshot.raw),
          timestamp,
          timestamp,
        ],
      }
      : {
        sql: `UPDATE portal_orders
         SET customer_name=?, pickup_location=?, dropoff_location=?, pickup_datetime=?,
             dropoff_datetime=?, vehicle=?, status=?, reference=?, raw_json=?,
             captured_at=?, updated_at=?
         WHERE id=?`,
        params: [
          snapshot.customerName,
          snapshot.pickupLocation,
          snapshot.dropoffLocation,
          snapshot.pickupDatetime,
          snapshot.dropoffDatetime,
          snapshot.vehicle,
          snapshot.status,
          snapshot.reference,
          JSON.stringify(snapshot.raw),
          timestamp,
          timestamp,
          portalOrderId,
        ],
      };

    if (!eventType) {
      await this.batch([snapshotStatement]);
      return false;
    }
    const pendingEvents = await this.query(
      `SELECT event_type, previous_fingerprint, changed_fields_json
       FROM portal_order_events
       WHERE portal_order_id=? AND event_type <> 'baseline' AND review_status='pending'
       ORDER BY observed_at, id`,
      [portalOrderId],
    );
    const cumulativeEvent = mergePendingPortalEvents(pendingEvents, {
      eventType,
      previousFingerprint,
      changedFields,
    });
    const supersedeStatement = {
      sql: `UPDATE portal_order_events
       SET review_status='dismissed', reviewed_by='system:superseded', reviewed_at=?
       WHERE portal_order_id=? AND event_type <> 'baseline' AND review_status='pending'`,
      params: [timestamp, portalOrderId],
    };
    const eventStatement = {
      sql: `INSERT INTO portal_order_events
       (id, portal_order_id, provider_id, account_label, order_ref, event_type,
        current_fingerprint, previous_fingerprint, normalized_snapshot_json,
        changed_fields_json, provider_status, review_status, observed_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
      params: [
        randomUUID(),
        portalOrderId,
        providerId,
        accountLabel,
        snapshot.orderRef,
        cumulativeEvent.eventType,
        currentFingerprint,
        cumulativeEvent.previousFingerprint,
        JSON.stringify(normalizeSnapshot(snapshot)),
        JSON.stringify(cumulativeEvent.changedFields),
        snapshot.status,
        timestamp,
        timestamp,
      ],
    };
    const results = await this.batch([snapshotStatement, supersedeStatement, eventStatement]);
    return Number(results[2]?.meta?.changes || 0) === 1;
  }

  async verifyListBinding(providerId, accountLabel, evidence) {
    await this.verifyBinding(providerId, accountLabel, 'order_list', ['new_booking'], evidence);
  }

  async verifyDetailBinding(providerId, accountLabel, evidence) {
    await this.verifyBinding(providerId, accountLabel, 'order_detail', [], evidence);
  }

  async verifyClassifierBinding(providerId, accountLabel, supportedEventTypes, evidence) {
    await this.verifyBinding(
      providerId,
      accountLabel,
      'event_classifier',
      supportedEventTypes,
      evidence,
    );
  }

  async verifyBinding(providerId, accountLabel, purpose, supportedEventTypes, evidence) {
    const timestamp = nowIso();
    await this.execute(
      `UPDATE ota_portal_recipe_bindings
       SET capability_status='verified', supported_event_types_json=?,
           evidence_json=?, blocker=NULL, last_verified_at=?, updated_at=?
       WHERE provider_id=? AND account_label=? AND purpose=?`,
      [
        JSON.stringify(supportedEventTypes),
        JSON.stringify(evidence),
        timestamp,
        timestamp,
        providerId,
        accountLabel,
        purpose,
      ],
    );
  }
}

const SNAPSHOT_KEYS = [
  'orderRef',
  'customerName',
  'pickupLocation',
  'dropoffLocation',
  'pickupDatetime',
  'dropoffDatetime',
  'vehicle',
  'status',
  'reference',
];

const normalizeText = (value) => String(value ?? '').trim().replace(/\s+/g, ' ').toLowerCase();

const normalizeSnapshot = (snapshot) => Object.fromEntries(
  SNAPSHOT_KEYS.map((key) => [key, normalizeText(snapshot[key])]),
);

export function portalSnapshotFingerprint(snapshot) {
  const normalized = JSON.stringify(normalizeSnapshot(snapshot));
  let hash = 2166136261;
  for (let index = 0; index < normalized.length; index += 1) {
    hash ^= normalized.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `po-${(hash >>> 0).toString(16)}`;
}

function changedSnapshotFields(previous, current) {
  const before = normalizeSnapshot(previous);
  const after = normalizeSnapshot(current);
  return SNAPSHOT_KEYS.filter((key) => before[key] !== after[key]);
}

function snapshotFromRow(row) {
  return Object.freeze({
    orderRef: row.order_ref,
    customerName: row.customer_name,
    pickupLocation: row.pickup_location,
    dropoffLocation: row.dropoff_location,
    pickupDatetime: row.pickup_datetime,
    dropoffDatetime: row.dropoff_datetime,
    vehicle: row.vehicle,
    status: row.status,
    reference: row.reference,
  });
}

export function classifyPortalSnapshotEvent({
  previous,
  snapshot,
  hasBaseline,
  classifier,
  changedFields,
  previousFingerprint,
  currentFingerprint,
}) {
  if (!previous) return hasBaseline ? 'new_booking' : 'baseline';
  if (previousFingerprint === currentFingerprint) return null;
  const currentStatus = normalizeText(snapshot.status);
  const previousStatus = normalizeText(previous.status);
  if (
    classifier.verified
    && classifier.supported.includes('cancellation')
    && classifier.cancelledStatuses.includes(currentStatus)
    && currentStatus !== previousStatus
  ) {
    return 'cancellation';
  }
  if (classifier.verified && classifier.supported.includes('change') && changedFields.length > 0) {
    return 'change';
  }
  return 'unknown';
}

export function mergePendingPortalEvents(pendingEvents, currentEvent) {
  const eventTypes = pendingEvents.map((event) => String(event.event_type || 'unknown'));
  const eventType = currentEvent.eventType === 'cancellation'
    ? 'cancellation'
    : eventTypes.includes('new_booking')
      ? 'new_booking'
      : currentEvent.eventType === 'unknown' || eventTypes.includes('unknown')
        ? 'unknown'
        : currentEvent.eventType;
  const changedFields = [...new Set([
    ...pendingEvents.flatMap((event) => parseJsonArray(event.changed_fields_json)),
    ...currentEvent.changedFields,
  ])];
  return Object.freeze({
    eventType,
    previousFingerprint: pendingEvents[0]?.previous_fingerprint ?? currentEvent.previousFingerprint,
    changedFields,
  });
}

function parseJsonArray(value) {
  try {
    const parsed = JSON.parse(value || '[]');
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}

function parseJsonObject(value) {
  try {
    const parsed = JSON.parse(value || '{}');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}
