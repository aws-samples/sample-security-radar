// WAF demo gate: every request is refused here (401 + WWW-Authenticate — identifiably this gate). AWS WAF runs
// before CloudFront Functions, so the web ACL still inspects, counts and labels each request; once a rule is
// promoted to Block the same request is stopped by WAF instead (403). There is no content behind this distribution.
function handler(event) {
  return {
    statusCode: 401,
    statusDescription: 'Unauthorized',
    headers: {
      'www-authenticate': { value: 'Basic realm="security-radar-waf-demo"' },
      'cache-control': { value: 'no-store' }
    }
  };
}
