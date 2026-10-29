// CloudFront Function (viewer-request): HTTP Basic auth against SHA-256 hashes kept in CloudFront
// KeyValueStore (key "basic_auth_sha256" = comma-separated sha256_hex("Basic " + base64(user:pass)), one per
// allowed user — the primary user plus aliases from the secret, scripts/set-ui-auth.sh). The plaintext
// credential lives only in Secrets Manager. FAIL CLOSED: missing header, missing/unreadable hash, or any
// error ⇒ 401. Owner accepted the risk of a self-managed shared credential (2026-10-23, DESIGN §8).
import cf from 'cloudfront';
const crypto = require('crypto');
const kvs = cf.kvs();

const DENY = {
  statusCode: 401,
  statusDescription: 'Unauthorized',
  headers: {
    'www-authenticate': { value: 'Basic realm="Security Radar", charset="UTF-8"' },
    'cache-control': { value: 'no-store' },
  },
};

async function handler(event) {
  const req = event.request;
  const auth = req.headers.authorization;
  if (!auth || !auth.value) return DENY;
  let expected;
  try {
    expected = await kvs.get('basic_auth_sha256', { format: 'string' });
  } catch (e) {
    return DENY;
  }
  if (!expected) return DENY;
  // cloudfront-js-2.0 has no for...of (live 503 on 2026-10-26) — plain index loops only
  const parts = expected.split(',');
  const got = crypto.createHash('sha256').update(auth.value).digest('hex');
  let ok = 0;
  let valid = 0;
  for (let k = 0; k < parts.length; k++) {  // every entry is compared: timing does not reveal which user matched
    const h = parts[k];
    if (h.length !== 64) continue;  // malformed entries never match
    valid++;
    let diff = 0;
    for (let i = 0; i < 64; i++) diff |= got.charCodeAt(i) ^ h.charCodeAt(i);
    ok |= diff === 0 ? 1 : 0;
  }
  return valid > 0 && ok ? req : DENY;
}
