import { chromium } from 'playwright-core';

const API_BASE = 'https://api.browser-use.com/api/v2';

export class BrowserUseClient {
  constructor(apiKey) {
    this.apiKey = apiKey;
  }

  async request(path, init) {
    const response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        'content-type': 'application/json',
        'x-browser-use-api-key': this.apiKey,
        ...(init?.headers || {}),
      },
      signal: AbortSignal.timeout(30_000),
    });
    const body = await response.json().catch(() => null);
    if (!response.ok || !body) {
      const error = new Error('Browser Use request failed');
      error.code = 'browser_unavailable';
      throw error;
    }
    return body;
  }

  async createProfile(name) {
    const body = await this.request('/profiles', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
    const profileId = body.id || body.profileId || body.profile?.id;
    if (!profileId) {
      const error = new Error('Browser Use profile was not created');
      error.code = 'browser_unavailable';
      throw error;
    }
    return String(profileId);
  }

  async startBrowser(profileId) {
    const body = await this.request('/browsers', {
      method: 'POST',
      body: JSON.stringify({
        profileId,
        timeout: 20,
      }),
    });
    const browser = body.browser || body;
    const id = browser.id || browser.browserId || body.id;
    const cdpUrl = browser.cdpUrl || browser.cdp_url || body.cdpUrl;
    const liveUrl = browser.liveUrl || browser.live_url || body.liveUrl;
    if (!id || !cdpUrl || !liveUrl) {
      const error = new Error('Browser Use session was incomplete');
      error.code = 'browser_unavailable';
      throw error;
    }
    return Object.freeze({
      id: String(id),
      cdpUrl: String(cdpUrl),
      liveUrl: String(liveUrl),
    });
  }

  async stopBrowser(browserId) {
    await this.request(`/browsers/${encodeURIComponent(browserId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ action: 'stop' }),
    });
  }

  async connect(cdpUrl) {
    let lastError;
    for (let attempt = 0; attempt < 8; attempt += 1) {
      try {
        return await chromium.connectOverCDP(cdpUrl, { timeout: 20_000 });
      } catch (error) {
        lastError = error;
        await delay(1_000 + attempt * 500);
      }
    }
    const unavailable = new Error('Browser connection failed', { cause: lastError });
    unavailable.code = 'browser_unavailable';
    throw unavailable;
  }
}

export async function browserPage(browser, cookieJson = null) {
  const contexts = browser.contexts();
  const context = contexts[0] || await browser.newContext();
  if (cookieJson) {
    const cookies = parseCookies(cookieJson);
    if (cookies.length > 0) await context.addCookies(cookies);
  }
  const pages = context.pages();
  const page = pages[0] || await context.newPage();
  return page;
}

function parseCookies(cookieJson) {
  try {
    const parsed = JSON.parse(cookieJson);
    const list = Array.isArray(parsed) ? parsed : parsed?.cookies;
    if (!Array.isArray(list)) return [];
    return list.flatMap((cookie) => {
      if (!cookie?.name || !cookie?.value || !cookie?.domain) return [];
      const sameSite = ['Strict', 'Lax', 'None'].includes(cookie.sameSite)
        ? cookie.sameSite
        : 'Lax';
      const normalized = {
        name: String(cookie.name),
        value: String(cookie.value),
        domain: String(cookie.domain),
        path: String(cookie.path || '/'),
        httpOnly: Boolean(cookie.httpOnly),
        secure: Boolean(cookie.secure),
        sameSite,
      };
      return Number.isFinite(cookie.expires)
        ? [{ ...normalized, expires: Number(cookie.expires) }]
        : [normalized];
    });
  } catch {
    return [];
  }
}

export const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
