import { sanitizeCapturedValue } from './security.mjs';
import { delay } from './browser-use.mjs';

const ORDER_REF_KEYS = [
  'orderNumber', 'bookingNumber', 'bookingNo', 'booking_no', 'confirmationNumber',
  'confirmationNo', 'confirmNo', 'order_id', 'oid', 'orderId', 'orderNo', 'order_no',
  'reservationNo', 'purchaseOrderId', 'reference', 'ref', 'id',
];
const CUSTOMER_KEYS = [
  'cust_full_name', 'customer_name', 'customerName', 'clientEName', 'guestName',
  'contactName', 'contact_name', 'renterName', 'driverName',
];
const PICKUP_KEYS = [
  'pickup_store', 'pickup_location', 'pickupLocation', 'pickupStore', 'pickup_branch',
  'voucherPickupLocation', 'pickupAddress', 'pickUpLocation', 'pickUpStoreName',
  'pickUpAddress', 'pickUpStoreCode',
];
const DROPOFF_KEYS = [
  'dropoff_store', 'dropoff_location', 'dropoffLocation', 'dropoffStore', 'return_branch',
  'voucherDropoffLocation', 'dropoffAddress', 'returnLocation', 'returnStoreName',
  'returnAddress', 'returnStoreCode',
];
const PICKUP_DATE_KEYS = [
  'pickup_datetime', 'pickupDatetime', 'pickup_time', 'pickupTime', 'pickup_date',
  'rentalStart', 'voucherPickupDate', 'pickupDateTime', 'pickUpTime',
  'pickUpDate.datetime', 'pickUpDate',
];
const DROPOFF_DATE_KEYS = [
  'dropoff_datetime', 'dropoffDatetime', 'dropoff_time', 'dropoffTime', 'return_date',
  'rentalEnd', 'voucherDropoffDate', 'dropoffDateTime', 'returnTime',
  'returnDate.datetime', 'returnDate',
];
const VEHICLE_KEYS = [
  'vehicle', 'voucherVehicle', 'carCategory', 'group_title', 'carName', 'car_name',
  'vehicleName', 'vehicleModel', 'vehicleProduct', 'skuName', 'carModelName',
  'modelName',
];
const STATUS_KEYS = ['order_status', 'status', 'orderStatus', 'statusDesc', 'state'];
const REFERENCE_KEYS = [
  'confirmationNumber', 'reference', 'ref', 'agent_ref', 'vendorConfirmCode',
  'confirmNo', 'voucherNo',
];

export async function capturePortalList(page, account, paginationEvidence = null, wait = delay) {
  if (!account.listUrl || !account.responsePattern) {
    const error = new Error('Order list route is not verified');
    error.code = 'list_route_unverified';
    throw error;
  }
  const intercepted = [];
  const listener = async (response) => {
    if (!response.url().includes(account.responsePattern)) return;
    try {
      const contentType = response.headers()['content-type'] || '';
      if (!contentType.includes('json')) return;
      intercepted.push(sanitizeCapturedValue(await response.json()));
    } catch {
      // A malformed non-order response is ignored; the DOM fallback still runs.
    }
  };
  page.on('response', listener);
  try {
    await page.goto(account.listUrl, {
      waitUntil: 'domcontentloaded',
      timeout: 60_000,
    });
    await wait(4_000);
    const pagination = normalizePaginationConfig(paginationEvidence);
    let pages = 1;
    let paginationComplete = pagination?.mode === 'single_page';
    const pagedDomRows = [];
    if (pagination?.mode === 'next_button') {
      paginationComplete = false;
      while (pages < pagination.maxPages) {
        pagedDomRows.push(...await extractDomRows(page));
        const next = page.locator(pagination.nextSelector).first();
        const visible = await next.isVisible().catch(() => false);
        const disabled = await next.isDisabled().catch(() => false)
          || await next.getAttribute('aria-disabled').then((value) => value === 'true').catch(() => false);
        if (!visible || disabled) {
          paginationComplete = true;
          break;
        }
        await next.click({ timeout: 15_000 });
        await wait(3_000);
        pages += 1;
      }
      pagedDomRows.push(...await extractDomRows(page));
    }
    const apiRows = intercepted.flatMap((payload) => extractRowsFromCapture(payload));
    const domRows = apiRows.length > 0
      ? []
      : pagination?.mode === 'next_button'
        ? pagedDomRows
        : await extractDomRows(page);
    const rows = deduplicateRows([...apiRows, ...domRows].map(mapOrderRow).filter(Boolean));
    if (pagination?.mode === 'api_total') {
      const totals = intercepted.flatMap((payload) => findPaginationTotals(payload));
      paginationComplete = totals.length > 0 && Math.max(...totals) <= rows.length;
    }
    return Object.freeze({
      rows,
      pageUrl: page.url(),
      pageText: await safePageText(page),
      evidenceKind: apiRows.length > 0 ? 'fixed_order_api' : 'order_list_dom',
      paginationEvidence: Object.freeze({
        complete: paginationComplete,
        mode: pagination?.mode ?? 'unverified',
        pages,
      }),
    });
  } finally {
    page.off('response', listener);
  }
}

export function normalizePaginationConfig(evidence) {
  if (!evidence || evidence.directEvidenceVerified !== true) return null;
  if (evidence.mode === 'single_page' || evidence.mode === 'api_total') {
    return Object.freeze({ mode: evidence.mode });
  }
  if (evidence.mode !== 'next_button') return null;
  const nextSelector = String(evidence.nextSelector || '').trim();
  const maxPages = Number(evidence.maxPages);
  if (!nextSelector || nextSelector.length > 500) return null;
  if (!Number.isInteger(maxPages) || maxPages < 2 || maxPages > 100) return null;
  return Object.freeze({ mode: 'next_button', nextSelector, maxPages });
}

export function buildPortalDetailUrl(account, orderRef, evidence) {
  if (!evidence || evidence.directEvidenceVerified !== true) {
    throw Object.assign(new Error('Detail recipe is unverified'), { code: 'detail_recipe_unverified' });
  }
  const template = String(evidence.urlTemplate || '').trim();
  if (!template.includes('{orderRef}') || template.length > 2_048) {
    throw Object.assign(new Error('Detail recipe is unverified'), { code: 'detail_recipe_unverified' });
  }
  const detailUrl = new URL(template.replaceAll('{orderRef}', encodeURIComponent(orderRef)));
  if (
    detailUrl.protocol !== 'https:'
    || !account.allowedHosts.includes(detailUrl.hostname)
  ) {
    throw Object.assign(new Error('Detail URL is not allowlisted'), { code: 'detail_url_rejected' });
  }
  if (detailUrl.username || detailUrl.password) {
    throw Object.assign(new Error('Detail URL is not allowlisted'), { code: 'detail_url_rejected' });
  }
  const secretParam = [...detailUrl.searchParams.keys()].some((key) =>
    /token|secret|auth|signature|session|api.?key/i.test(key));
  if (secretParam) {
    throw Object.assign(new Error('Detail URL contains secret parameters'), { code: 'detail_url_rejected' });
  }
  return detailUrl.toString();
}

export async function capturePortalDetail(page, account, row, evidence) {
  const detailUrl = buildPortalDetailUrl(account, row.orderRef, evidence);
  await page.goto(detailUrl, {
    waitUntil: 'domcontentloaded',
    timeout: 60_000,
  });
  await delay(3_000);
  const pageUrl = page.url();
  const url = new URL(pageUrl);
  if (!account.allowedHosts.includes(url.hostname)) {
    throw Object.assign(new Error('Detail URL is not allowlisted'), { code: 'detail_url_rejected' });
  }
  const text = await safePageText(page);
  if (!text.toLowerCase().includes(String(row.orderRef).toLowerCase())) {
    throw Object.assign(new Error('Detail order reference was not proven'), { code: 'detail_recipe_unverified' });
  }
  return Object.freeze({
    detailCount: 1,
    evidence: Object.freeze({
      mode: 'url_template',
      host: url.hostname,
      path: url.pathname,
      orderReferenceMatched: true,
    }),
  });
}

export function mapOrderRow(rawRow) {
  if (!rawRow || typeof rawRow !== 'object' || Array.isArray(rawRow)) return null;
  const raw = sanitizeCapturedValue(rawRow);
  const values = flattenValues(raw);
  const pick = (...keys) => {
    for (const key of keys) {
      const direct = raw[key];
      const value = direct
        ?? values.get(String(key).toLowerCase())
        ?? values.get(normalizeKey(key));
      if (value != null && typeof value !== 'object' && String(value).trim()) return String(value).trim();
    }
    return null;
  };
  const orderRef = pick(...ORDER_REF_KEYS);
  if (!orderRef || orderRef.length > 200) return null;
  const vehicle = pick(...VEHICLE_KEYS)
    || [pick('brand_name', 'brand'), pick('model_name', 'model')].filter(Boolean).join(' ')
    || null;
  return Object.freeze({
    orderRef,
    customerName: pick(...CUSTOMER_KEYS),
    pickupLocation: pick(...PICKUP_KEYS),
    dropoffLocation: pick(...DROPOFF_KEYS),
    pickupDatetime: pick(...PICKUP_DATE_KEYS),
    dropoffDatetime: pick(...DROPOFF_DATE_KEYS),
    vehicle,
    status: pick(...STATUS_KEYS),
    reference: pick(...REFERENCE_KEYS),
    raw,
  });
}

export function proveExactAccount({
  account,
  pageUrl,
  pageText,
  capturedRows,
  priorOrderReferences,
  safeUsername,
}) {
  const url = new URL(pageUrl);
  if (!account.allowedHosts.includes(url.hostname)) return false;
  const normalizedText = String(pageText || '').toLowerCase();
  const normalizedUrl = pageUrl.toLowerCase();
  const accountIdentifier = distinctAccountIdentifier(account, safeUsername);
  if (
    accountIdentifier
    && (normalizedText.includes(accountIdentifier) || normalizedUrl.includes(accountIdentifier))
  ) return true;
  const capturedRefs = new Set(capturedRows.map((row) => row.orderRef));
  return [...priorOrderReferences].some((orderRef) => capturedRefs.has(orderRef));
}

function distinctAccountIdentifier(account, safeUsername) {
  const normalized = String(safeUsername || '').trim().toLowerCase();
  if (normalized.length < 4) return null;
  const compact = normalized.replace(/[^a-z0-9]/g, '');
  const genericIdentifiers = [
    account.accountLabel,
    ...account.accountLabel.split('-'),
    ...account.providerId.split('-'),
    'easy rent bali',
    'easyrent',
    'ainno',
    'yesaway',
    'admin',
    'administrator',
    'supplier',
    'support',
    'reservation',
    'reservations',
  ].map((value) => String(value).toLowerCase().replace(/[^a-z0-9]/g, ''));
  return genericIdentifiers.includes(compact) ? null : normalized;
}

export function isLoginPage(account, pageUrl, pageText) {
  const current = new URL(pageUrl);
  const login = new URL(account.loginUrl);
  if (current.hostname !== login.hostname) return false;
  const loginPath = login.pathname.replace(/\/+$/, '');
  const currentPath = current.pathname.replace(/\/+$/, '');
  if (currentPath === loginPath) return true;
  if (/\/(?:login|signin)(?:\/|$)/i.test(currentPath)) return true;
  const text = String(pageText || '').slice(0, 20_000);
  return /password[\s\S]{0,120}(?:sign in|log in|login)|(?:sign in|log in|login)[\s\S]{0,120}password/i.test(text);
}

function flattenValues(node, prefix = '', values = new Map(), depth = 0) {
  if (!node || typeof node !== 'object' || Array.isArray(node) || depth > 6) return values;
  for (const [key, value] of Object.entries(node)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (value != null && typeof value !== 'object' && String(value).trim()) {
      if (!values.has(key.toLowerCase())) values.set(key.toLowerCase(), value);
      if (!values.has(path.toLowerCase())) values.set(path.toLowerCase(), value);
      if (!values.has(normalizeKey(key))) values.set(normalizeKey(key), value);
      if (!values.has(normalizeKey(path))) values.set(normalizeKey(path), value);
    } else if (value && typeof value === 'object') {
      flattenValues(value, path, values, depth + 1);
    }
  }
  return values;
}

const normalizeKey = (key) => String(key).toLowerCase().replace(/[^a-z0-9]/g, '');

function rowArrays(node, output = [], depth = 0) {
  if (!node || depth > 8) return output;
  if (Array.isArray(node)) {
    if (node.some((item) => item && typeof item === 'object' && !Array.isArray(item))) {
      output.push(node);
    }
    for (const item of node) rowArrays(item, output, depth + 1);
    return output;
  }
  if (typeof node === 'object') {
    for (const value of Object.values(node)) rowArrays(value, output, depth + 1);
  }
  return output;
}

function findPaginationTotals(payload, depth = 0) {
  if (!payload || typeof payload !== 'object' || depth > 8) return [];
  if (Array.isArray(payload)) {
    return payload.flatMap((value) => findPaginationTotals(value, depth + 1));
  }
  const totals = [];
  for (const [key, value] of Object.entries(payload)) {
    if (
      /^(total|totalCount|recordsTotal|recordCount)$/i.test(key)
      && Number.isInteger(Number(value))
      && Number(value) >= 0
    ) {
      totals.push(Number(value));
    } else if (value && typeof value === 'object') {
      totals.push(...findPaginationTotals(value, depth + 1));
    }
  }
  return totals;
}

function extractRowsFromCapture(payload) {
  const direct = payload?.result?.data
    || payload?.data?.rows
    || payload?.data?.list
    || (Array.isArray(payload?.data) ? payload.data : null)
    || payload?.rows
    || payload?.list
    || (Array.isArray(payload) ? payload : null);
  const candidates = [];
  if (Array.isArray(direct)) candidates.push(direct);
  candidates.push(...rowArrays(payload));
  let best = [];
  let bestScore = 0;
  for (const rows of candidates) {
    const sample = rows.filter((item) => item && typeof item === 'object' && !Array.isArray(item)).slice(0, 500);
    const score = sample.reduce((sum, item) => sum + (mapOrderRow(item) ? 1 : 0), 0);
    if (score > bestScore) {
      best = sample;
      bestScore = score;
    }
  }
  return bestScore > 0 ? best : [];
}

async function extractDomRows(page) {
  const rows = await page.locator('table').first().evaluate((table) => {
    const headers = [...table.querySelectorAll('thead th')]
      .map((cell) => cell.textContent?.trim() || '');
    return [...table.querySelectorAll('tbody tr')].slice(0, 500).map((row) => {
      const cells = [...row.querySelectorAll('td')].map((cell) => cell.textContent?.trim() || '');
      return Object.fromEntries(cells.map((value, index) => [headers[index] || `column_${index}`, value]));
    });
  }).catch(() => []);
  return Array.isArray(rows) ? rows : [];
}

async function safePageText(page) {
  return page.locator('body').innerText({ timeout: 10_000 })
    .then((text) => text.slice(0, 100_000))
    .catch(() => '');
}

function deduplicateRows(rows) {
  return [...new Map(rows.map((row) => [row.orderRef, row])).values()];
}
