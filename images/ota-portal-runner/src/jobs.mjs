import { BrowserUseClient, browserPage, delay } from './browser-use.mjs';
import { randomUUID } from 'node:crypto';
import {
  capturePortalDetail,
  capturePortalList,
  isLoginPage,
  proveExactAccount,
} from './capture.mjs';
import { getPortalAccount, portalAccountKey } from './config.mjs';
import { sanitizeRunnerError } from './security.mjs';

const LOGIN_WINDOW_MS = 20 * 60_000;

export class PortalJobRunner {
  constructor(config, d1) {
    this.config = config;
    this.d1 = d1;
    this.browserUse = new BrowserUseClient(config.browserUseApiKey);
    this.runningAccounts = new Set();
    this.queuePumpActive = false;
  }

  async claimAndStart(job, runnerRequestId) {
    const accountKey = portalAccountKey(job.providerId, job.accountLabel);
    if (this.runningAccounts.has(accountKey)) {
      const error = new Error('Account already running');
      error.code = 'job_not_claimed';
      throw error;
    }
    await this.d1.claimJob(job.jobId, runnerRequestId);
    this.runningAccounts.add(accountKey);
    setImmediate(() => {
      this.execute(job)
        .catch(() => {})
        .finally(() => {
          this.runningAccounts.delete(accountKey);
          void this.startNextQueuedJob();
        });
    });
  }

  async startNextQueuedJob() {
    if (this.queuePumpActive || this.runningAccounts.size > 0) return;
    this.queuePumpActive = true;
    try {
      const next = await this.d1.nextQueuedJob();
      if (next) await this.claimAndStart(next, randomUUID());
    } catch {
      // Another runner may have claimed the queued job; the next completion retries the pump.
    } finally {
      this.queuePumpActive = false;
    }
  }

  async execute(job) {
    let counts = { orderCount: 0, eventCount: 0, detailCount: 0 };
    try {
      if (job.action === 'login') {
        counts = await this.login(job);
      } else if (job.action === 'validate') {
        counts = await this.validate(job);
      } else {
        counts = await this.capture(job);
      }
      await this.d1.finishJob(job.jobId, { status: 'succeeded', ...counts });
      safeLog({ ...job, status: 'succeeded', ...counts });
    } catch (error) {
      const sanitizedError = sanitizeRunnerError(error);
      await this.d1.markAccount(job.providerId, job.accountLabel, {
        status: error?.code === 'session_expired' ? 'expired' : 'error',
        profileStatus: error?.code === 'session_expired' ? 'expired' : 'error',
      }).catch(() => {});
      await this.d1.finishJob(job.jobId, {
        status: 'failed',
        sanitizedError,
      }).catch(() => {});
      safeLog({ ...job, status: 'failed', sanitizedError });
    }
  }

  async login(job) {
    const account = getPortalAccount(job.providerId, job.accountLabel);
    const session = await this.openSession(job, account);
    try {
      const expiresAt = new Date(Date.now() + LOGIN_WINDOW_MS).toISOString();
      await this.d1.setLiveLogin(job.jobId, session.remote.liveUrl, expiresAt);
      await session.page.goto(account.loginUrl, {
        waitUntil: 'domcontentloaded',
        timeout: 60_000,
      });

      const deadline = Date.now() + LOGIN_WINDOW_MS;
      while (Date.now() < deadline) {
        const text = await pageText(session.page);
        if (!isLoginPage(account, session.page.url(), text)) {
          const proof = await this.captureAndProve(session.page, account, session.accountSecrets, {
            allowMissingList: true,
          });
          if (proof.verified) {
            await this.d1.markAccount(job.providerId, job.accountLabel, {
              status: 'active',
              profileStatus: 'active',
              verified: true,
            });
            return { orderCount: proof.rows.length, eventCount: 0, detailCount: 0 };
          }
        }
        await delay(5_000);
      }
      const error = new Error('Live login expired');
      error.code = 'session_expired';
      throw error;
    } finally {
      await this.closeSession(session);
    }
  }

  async validate(job) {
    const account = getPortalAccount(job.providerId, job.accountLabel);
    const session = await this.openSession(job, account);
    try {
      const proof = await this.captureAndProve(session.page, account, session.accountSecrets, {
        allowMissingList: true,
      });
      if (!proof.verified) {
        const error = new Error('Exact account mismatch');
        error.code = 'account_mismatch';
        throw error;
      }
      await this.d1.markAccount(job.providerId, job.accountLabel, {
        status: 'active',
        profileStatus: 'active',
        verified: true,
      });
      return { orderCount: proof.rows.length, eventCount: 0, detailCount: 0 };
    } finally {
      await this.closeSession(session);
    }
  }

  async capture(job) {
    const account = getPortalAccount(job.providerId, job.accountLabel);
    if (!account.listUrl) {
      const error = new Error('List route is unverified');
      error.code = 'list_route_unverified';
      throw error;
    }
    const capabilities = await this.d1.captureCapabilities(job.providerId, job.accountLabel);
    const listCapability = requireCaptureCapability(capabilities, 'order_list');
    const detailCapability = requireCaptureCapability(capabilities, 'order_detail');
    const classifierCapability = requireCaptureCapability(capabilities, 'event_classifier');
    const paginationEvidence = {
      ...(listCapability.evidence.pagination || {}),
      directEvidenceVerified: listCapability.evidence.directEvidenceVerified === true,
    };
    const classifierEvidence = normalizeClassifierCapability(classifierCapability);
    const session = await this.openSession(job, account);
    try {
      const first = await this.captureAndProve(session.page, account, session.accountSecrets, {
        paginationEvidence,
      });
      if (!first.verified) {
        const error = new Error('Exact account mismatch');
        error.code = 'account_mismatch';
        throw error;
      }
      if (!first.paginationEvidence?.complete) {
        const error = new Error('Pagination completeness is unverified');
        error.code = 'pagination_unverified';
        throw error;
      }
      const second = await this.captureAndProve(session.page, account, session.accountSecrets, {
        paginationEvidence,
      });
      if (!second.verified) {
        const error = new Error('Exact account mismatch');
        error.code = 'account_mismatch';
        throw error;
      }
      if (!second.paginationEvidence?.complete) {
        const error = new Error('Pagination completeness is unverified');
        error.code = 'pagination_unverified';
        throw error;
      }
      const firstFingerprints = new Map(first.rows.map((row) => [row.orderRef, snapshotFingerprint(row)]));
      const secondFingerprints = new Map(second.rows.map((row) => [row.orderRef, snapshotFingerprint(row)]));
      if (!sameFingerprintMap(firstFingerprints, secondFingerprints)) {
        const error = new Error('Repeated capture changed');
        error.code = 'duplicate_capture_failed';
        throw error;
      }
      const detailRow = first.rows[0];
      if (!detailRow) {
        const error = new Error('Detail capture requires one list order');
        error.code = 'detail_recipe_unverified';
        throw error;
      }
      const detail = await capturePortalDetail(
        session.page,
        account,
        detailRow,
        detailCapability.evidence,
      );
      await this.d1.verifyClassifierBinding(
        job.providerId,
        job.accountLabel,
        classifierEvidence.supportedEventTypes,
        classifierEvidence.evidence,
      );
      const firstSave = await this.d1.savePortalRows(job.providerId, job.accountLabel, first.rows);
      const secondSave = await this.d1.savePortalRows(job.providerId, job.accountLabel, second.rows);
      if (secondSave.eventCount !== 0) {
        const error = new Error('Repeated capture created events');
        error.code = 'duplicate_capture_failed';
        throw error;
      }
      await this.d1.markAccount(job.providerId, job.accountLabel, {
        status: 'active',
        profileStatus: 'active',
        verified: true,
      });
      await this.d1.verifyListBinding(job.providerId, job.accountLabel, {
        directEvidenceVerified: true,
        evidenceType: first.evidenceKind,
        pagination: paginationEvidence,
        exactAccount: true,
        duplicateCaptureEventCount: secondSave.eventCount,
        capturedOrderCount: firstSave.orderCount,
        verifiedAt: new Date().toISOString(),
      });
      await this.d1.verifyDetailBinding(job.providerId, job.accountLabel, {
        ...detail.evidence,
        directEvidenceVerified: true,
        verifiedAt: new Date().toISOString(),
      });
      return {
        orderCount: firstSave.orderCount,
        eventCount: firstSave.eventCount,
        detailCount: detail.detailCount,
      };
    } finally {
      await this.closeSession(session);
    }
  }

  async openSession(job, account) {
    const accountSecrets = await this.d1.getAccountSecrets(job.providerId, job.accountLabel);
    let profileId = accountSecrets.profileId;
    if (!profileId) {
      profileId = await this.browserUse.createProfile(`ota-${job.providerId}-${job.accountLabel}`);
      await this.d1.saveProfile(job.providerId, job.accountLabel, profileId, 'unconfigured');
    }
    const remote = await this.browserUse.startBrowser(profileId);
    let browser;
    try {
      browser = await this.browserUse.connect(remote.cdpUrl);
      const page = await browserPage(browser, accountSecrets.cookies);
      return Object.freeze({ account, accountSecrets, profileId, remote, browser, page });
    } catch (error) {
      await this.browserUse.stopBrowser(remote.id).catch(() => {});
      throw error;
    }
  }

  async closeSession(session) {
    await this.browserUse.stopBrowser(session.remote.id).catch(() => {});
    await session.browser.close().catch(() => {});
  }

  async captureAndProve(
    page,
    account,
    accountSecrets,
    { allowMissingList = false, paginationEvidence = null } = {},
  ) {
    if (!account.listUrl && allowMissingList) {
      await page.goto(account.loginUrl, {
        waitUntil: 'domcontentloaded',
        timeout: 60_000,
      });
      const text = await pageText(page);
      if (isLoginPage(account, page.url(), text)) {
        const error = new Error('Session expired');
        error.code = 'session_expired';
        throw error;
      }
      const verified = proveExactAccount({
        account,
        pageUrl: page.url(),
        pageText: text,
        capturedRows: [],
        priorOrderReferences: new Set(),
        safeUsername: accountSecrets.username,
      });
      return Object.freeze({ verified, rows: [], evidenceKind: 'authenticated_portal_page' });
    }
    const capture = await capturePortalList(page, account, paginationEvidence);
    if (isLoginPage(account, capture.pageUrl, capture.pageText)) {
      const error = new Error('Session expired');
      error.code = 'session_expired';
      throw error;
    }
    const priorOrderReferences = await this.d1.priorOrderReferences(
      account.providerId,
      account.accountLabel,
    );
    const verified = proveExactAccount({
      account,
      pageUrl: capture.pageUrl,
      pageText: capture.pageText,
      capturedRows: capture.rows,
      priorOrderReferences,
      safeUsername: accountSecrets.username,
    });
    return Object.freeze({ ...capture, verified });
  }
}

function requireCaptureCapability(capabilities, purpose) {
  const capability = capabilities.get(purpose);
  if (
    !capability
    || !['configured_unverified', 'verified'].includes(capability.status)
    || capability.evidence?.directEvidenceVerified !== true
  ) {
    const error = new Error(`${purpose} capability is unverified`);
    error.code = 'capability_unverified';
    throw error;
  }
  return capability;
}

function normalizeClassifierCapability(capability) {
  const supportedEventTypes = capability.supportedEventTypes.filter((eventType) =>
    eventType === 'cancellation' || eventType === 'change');
  const cancelledStatuses = Array.isArray(capability.evidence.cancelledStatuses)
    ? capability.evidence.cancelledStatuses.map((value) => String(value).trim().toLowerCase()).filter(Boolean)
    : [];
  if (
    supportedEventTypes.length === 0
    || (supportedEventTypes.includes('cancellation') && cancelledStatuses.length === 0)
  ) {
    const error = new Error('Classifier evidence is incomplete');
    error.code = 'classifier_unverified';
    throw error;
  }
  return Object.freeze({
    supportedEventTypes,
    evidence: Object.freeze({
      directEvidenceVerified: true,
      cancelledStatuses,
      evidenceType: String(capability.evidence.evidenceType || 'portal_status_evidence'),
      verifiedAt: new Date().toISOString(),
    }),
  });
}

async function pageText(page) {
  return page.locator('body').innerText({ timeout: 10_000 })
    .then((text) => text.slice(0, 100_000))
    .catch(() => '');
}

function snapshotFingerprint(row) {
  return JSON.stringify({
    orderRef: row.orderRef || '',
    customerName: row.customerName || '',
    pickupLocation: row.pickupLocation || '',
    dropoffLocation: row.dropoffLocation || '',
    pickupDatetime: row.pickupDatetime || '',
    dropoffDatetime: row.dropoffDatetime || '',
    vehicle: row.vehicle || '',
    status: row.status || '',
    reference: row.reference || '',
  });
}

function sameFingerprintMap(left, right) {
  if (left.size !== right.size) return false;
  return [...left].every(([key, value]) => right.get(key) === value);
}

function safeLog(entry) {
  process.stdout.write(`${JSON.stringify({
    event: 'portal_job_finished',
    jobId: entry.jobId,
    providerId: entry.providerId,
    accountLabel: entry.accountLabel,
    action: entry.action,
    status: entry.status,
    orderCount: Number(entry.orderCount || 0),
    eventCount: Number(entry.eventCount || 0),
    detailCount: Number(entry.detailCount || 0),
    error: entry.sanitizedError || null,
  })}\n`);
}
