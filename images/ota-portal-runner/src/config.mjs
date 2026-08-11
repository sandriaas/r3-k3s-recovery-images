const account = ({
  providerId,
  accountLabel,
  loginUrl,
  listUrl,
  responsePattern,
  brandHints,
}) => Object.freeze({
  providerId,
  accountLabel,
  loginUrl,
  listUrl,
  responsePattern,
  allowedHosts: Object.freeze([...new Set([
    new URL(loginUrl).hostname,
    ...(listUrl ? [new URL(listUrl).hostname] : []),
  ])]),
  brandHints: Object.freeze(brandHints),
});

export const portalAccountKey = (providerId, accountLabel) => `${providerId}/${accountLabel}`;

const entries = [
  account({
    providerId: 'cartrawler-supplier',
    accountLabel: 'easyrent',
    loginUrl: 'https://supplier.cartrawler.com/secure/login',
    listUrl: null,
    responsePattern: null,
    brandHints: ['easy rent bali', 'easyrent'],
  }),
  account({
    providerId: 'trip-cbooking',
    accountLabel: 'easyrent',
    loginUrl: 'https://cbooking.trip.com/pc/login',
    listUrl: 'https://cbooking.trip.com/webapp/zcb/order/order/orderList',
    responsePattern: 'queryOsdOrderList',
    brandHints: ['easy rent bali', 'easyrent', 'reservation@easyrentbali.com'],
  }),
  account({
    providerId: 'trip-cbooking',
    accountLabel: 'ainno',
    loginUrl: 'https://cbooking.trip.com/pc/login',
    listUrl: 'https://cbooking.trip.com/webapp/zcb/order/order/orderList',
    responsePattern: 'queryOsdOrderList',
    brandHints: ['ainno', 'ainnojayaabadi@gmail.com'],
  }),
  account({
    providerId: 'economycarrentals-sup',
    accountLabel: 'easyrent',
    loginUrl: 'https://suppliers.economycarrentals.com/suppliers/index',
    listUrl: 'https://suppliers.economycarrentals.com/suppliers/orders/active',
    responsePattern: 'suppliers/data/orders/active',
    brandHints: ['easy rent bali', 'easyrent', 'reservations@economycarrentals.com'],
  }),
  account({
    providerId: 'economybookings-mp',
    accountLabel: 'easyrent',
    loginUrl: 'https://marketplace.economybookings.com/s',
    listUrl: 'https://marketplace.economybookings.com/bookingHistory',
    responsePattern: 'bookingHistory/list',
    brandHints: ['easy rent bali', 'easyrent', 'support@easyrentbali.com'],
  }),
  account({
    providerId: 'economybookings-mp',
    accountLabel: 'ainno',
    loginUrl: 'https://marketplace.economybookings.com/s',
    listUrl: 'https://marketplace.economybookings.com/bookingHistory',
    responsePattern: 'bookingHistory/list',
    brandHints: ['ainno'],
  }),
  account({
    providerId: 'qbooking-solutions',
    accountLabel: 'easyrent',
    loginUrl: 'https://r.qbookingsolutions.com/backend.php/',
    listUrl: 'https://r.qbookingsolutions.com/backend.php/order/index',
    responsePattern: 'order/get_orders',
    brandHints: ['easy rent bali', 'easyrent', 'reservation@easyrentbali.com'],
  }),
  account({
    providerId: 'qbooking-solutions',
    accountLabel: 'ainno-yesaway',
    loginUrl: 'https://r.qbookingsolutions.com/backend.php/',
    listUrl: 'https://r.qbookingsolutions.com/backend.php/order/index',
    responsePattern: 'order/get_orders',
    brandHints: ['ainno', 'yesaway'],
  }),
];

export const PORTAL_ACCOUNTS = new Map(entries.map((item) => [
  portalAccountKey(item.providerId, item.accountLabel),
  item,
]));

export const CAPTURE_ACTIONS = new Set(['login', 'validate', 'capture']);

export function getPortalAccount(providerId, accountLabel) {
  return PORTAL_ACCOUNTS.get(portalAccountKey(providerId, accountLabel)) ?? null;
}

export function loadConfig(env = process.env) {
  const required = [
    'OTA_PORTAL_RUNNER_SIGNING_SECRET',
    'BROWSER_USE_API_KEY',
    'CLOUDFLARE_ACCOUNT_ID',
    'CLOUDFLARE_API_TOKEN',
    'D1_DATABASE_ID',
    'SCRAPE_CRED_KEY',
  ];
  const missing = required.filter((name) => !String(env[name] || '').trim());
  if (missing.length > 0) throw new Error('Runner configuration is incomplete');
  if (String(env.OTA_PORTAL_RUNNER_SIGNING_SECRET).length < 32) {
    throw new Error('Runner signing secret is invalid');
  }
  const port = Number(env.OTA_PORTAL_RUNNER_PORT || env.PORT || 8080);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error('Runner port is invalid');
  }
  return Object.freeze({
    port,
    signingSecret: String(env.OTA_PORTAL_RUNNER_SIGNING_SECRET),
    browserUseApiKey: String(env.BROWSER_USE_API_KEY),
    cloudflareAccountId: String(env.CLOUDFLARE_ACCOUNT_ID),
    cloudflareApiToken: String(env.CLOUDFLARE_API_TOKEN),
    d1DatabaseId: String(env.D1_DATABASE_ID),
    scrapeCredKey: String(env.SCRAPE_CRED_KEY),
  });
}
