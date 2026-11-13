"""Feeds and exchange announcement endpoints admitted by scripts/source-onboard.py (2026-11-10).

Generated from the onboarding verdicts (build/source-onboard.verdicts.json, build/exchange-onboard.verdicts.json):
every row parsed to entries from the radar's AWS egress and published within 30 days. Candidates: the sec-intel
registry (aws-gcr-web3/sec-intel src/sec_intel/sources.py), the top-100 CoinMarketCap exchanges (build/exchanges), and
additions. Tier: vendor / government / first-line research / an exchange's own notices = T1; media = T2; aggregators
(Reddit, Lobsters, Google News, distro trackers) = T3. A new feed is a row here after it passes onboarding.
"""
from __future__ import annotations

# (source_id, name, tier, org, domain, parser, url, cadence_min)
FEEDS: tuple[tuple[str, str, str, str, str | None, str, str, int], ...] = (
    # --- cn
    ('seebug', 'Seebug Paper', 'T2', 'seebug', None, 'feed', 'https://paper.seebug.org/rss/', 30),
    # --- exchange
    ('ex_crypto_com_status', 'Crypto.com 状态页', 'T1', 'ex_crypto_com_status', 'web3', 'feed', 'https://status.crypto.com/history.rss', 10),
    # --- gnews
    ('gn_0day', 'Google News · zero-days', 'T3', 'gn_0day', None, 'feed', 'https://news.google.com/rss/search?q=zero-day+OR+%22actively+exploited%22+when:1d&hl=en-US&gl=US&ceid=US:en', 10),
    ('gn_crypto_hack', 'Google News · crypto hacks', 'T3', 'gn_crypto_hack', None, 'feed', 'https://news.google.com/rss/search?q=crypto+hack+OR+exploit+OR+drained+OR+stolen+when:1d&hl=en-US&gl=US&ceid=US:en', 10),
    ('gn_exchange_halt', 'Google News · exchange halts', 'T3', 'gn_exchange_halt', None, 'feed', 'https://news.google.com/rss/search?q=exchange+%22suspends+withdrawals%22+OR+%22hot+wallet%22+when:2d&hl=en-US&gl=US&ceid=US:en', 10),
    ('gn_exchange_zh', 'Google 新闻 · 交易所被盗/暂停提币', 'T3', 'gn_exchange_zh', None, 'feed', 'https://news.google.com/rss/search?q=%E4%BA%A4%E6%98%93%E6%89%80+%E8%A2%AB%E7%9B%97+OR+%E6%9A%82%E5%81%9C%E6%8F%90%E5%B8%81+OR+%E9%BB%91%E5%AE%A2+when:2d&hl=zh-CN&gl=CN&ceid=CN:zh-Hans', 10),
    # --- gov
    ('cccs', 'Canadian Centre for Cyber Security', 'T1', 'cccs', None, 'feed', 'https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en', 15),
    ('cert_eu', 'CERT-EU', 'T1', 'cert_eu', None, 'feed', 'https://cert.europa.eu/publications/security-advisories-rss', 15),
    ('cert_fr', 'CERT-FR', 'T1', 'cert_fr', None, 'feed', 'https://www.cert.ssi.gouv.fr/feed/', 15),
    ('ic3', 'FBI IC3 PSAs', 'T1', 'ic3', None, 'feed', 'https://www.ic3.gov/PSA/RSS', 15),
    ('jpcert', 'JPCERT/CC', 'T1', 'jpcert', None, 'feed', 'https://www.jpcert.or.jp/english/rss/jpcert-en.rdf', 15),
    ('ncsc_uk', 'NCSC UK', 'T1', 'ncsc_uk', None, 'feed', 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml', 15),
    ('hkcert', 'HKCERT', 'T3', 'hkcert', None, 'feed', 'https://www.hkcert.org/getrss/security-bulletin', 15),
    # --- news
    ('sans_isc', 'SANS Internet Storm Center', 'T1', 'sans_isc', None, 'feed', 'https://isc.sans.edu/rssfeed_full.xml', 15),
    ('ars', 'Ars Technica · Security', 'T2', 'ars', None, 'feed', 'https://arstechnica.com/security/feed/', 15),
    ('bankinfosec', 'BankInfoSecurity', 'T2', 'bankinfosec', None, 'feed', 'https://www.bankinfosecurity.com/rss-feeds', 15),
    ('csoonline', 'CSO Online', 'T2', 'csoonline', None, 'feed', 'https://www.csoonline.com/feed/', 15),
    ('cyberscoop', 'CyberScoop', 'T2', 'cyberscoop', None, 'feed', 'https://cyberscoop.com/feed/', 15),
    ('cybersecdive', 'Cybersecurity Dive', 'T2', 'cybersecdive', None, 'feed', 'https://www.cybersecuritydive.com/feeds/news/', 15),
    ('darkreading', 'Dark Reading', 'T2', 'darkreading', None, 'feed', 'https://www.darkreading.com/rss.xml', 15),
    ('gbhackers', 'GBHackers', 'T2', 'gbhackers', None, 'feed', 'https://gbhackers.com/feed/', 15),
    ('hackread', 'HackRead', 'T2', 'hackread', None, 'feed', 'https://hackread.com/feed/', 15),
    ('infosecmag', 'Infosecurity Magazine', 'T2', 'infosecmag', None, 'feed', 'https://www.infosecurity-magazine.com/rss/news/', 15),
    ('krebs', 'Krebs on Security', 'T2', 'krebs', None, 'feed', 'https://krebsonsecurity.com/feed/', 15),
    ('register', 'The Register · Security', 'T2', 'register', None, 'feed', 'https://www.theregister.com/security/headlines.atom', 15),
    ('risky', 'Risky Business News', 'T2', 'risky', None, 'feed', 'https://news.risky.biz/rss/', 15),
    ('schneier', 'Schneier on Security', 'T2', 'schneier', None, 'feed', 'https://www.schneier.com/feed/atom/', 15),
    ('secaffairs', 'Security Affairs', 'T2', 'secaffairs', None, 'feed', 'https://securityaffairs.com/feed', 15),
    ('techcrunch_sec', 'TechCrunch · Security', 'T2', 'techcrunch_sec', None, 'feed', 'https://techcrunch.com/category/security/feed/', 15),
    ('therecord', 'The Record', 'T2', 'therecord', None, 'feed', 'https://therecord.media/feed', 15),
    ('wired', 'WIRED · Security', 'T2', 'wired', None, 'feed', 'https://www.wired.com/feed/category/security/latest/rss', 15),
    ('lobsters_sec', 'Lobsters · security', 'T3', 'lobsters_sec', None, 'feed', 'https://lobste.rs/t/security.rss', 15),
    ('netsec', 'r/netsec', 'T3', 'netsec', None, 'feed', 'https://www.reddit.com/r/netsec/.rss', 15),
    # --- research
    ('cpr', 'Check Point Research', 'T1', 'cpr', None, 'feed', 'https://research.checkpoint.com/feed/', 60),
    ('datadog_sl', 'Datadog Security Labs', 'T1', 'datadog_sl', None, 'feed', 'https://securitylabs.datadoghq.com/rss/feed.xml', 60),
    ('eset', 'ESET WeLiveSecurity', 'T1', 'eset', None, 'feed', 'https://www.welivesecurity.com/en/rss/feed/', 60),
    ('gtig', 'Google Threat Intelligence', 'T1', 'gtig', None, 'feed', 'https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/', 60),
    ('ms_sec', 'Microsoft Security Blog', 'T1', 'ms_sec', None, 'feed', 'https://www.microsoft.com/en-us/security/blog/feed/', 60),
    ('p0', 'Google Project Zero', 'T1', 'p0', None, 'feed', 'https://googleprojectzero.blogspot.com/feeds/posts/default', 60),
    ('s1labs', 'SentinelLabs', 'T1', 's1labs', None, 'feed', 'https://www.sentinelone.com/labs/feed/', 60),
    ('securelist', 'Kaspersky Securelist', 'T1', 'securelist', None, 'feed', 'https://securelist.com/feed/', 60),
    ('socket', 'Socket Blog', 'T1', 'socket', None, 'feed', 'https://socket.dev/api/blog/feed.atom', 60),
    ('talos', 'Cisco Talos', 'T1', 'talos', None, 'feed', 'https://blog.talosintelligence.com/rss/', 60),
    ('unit42', 'Unit 42', 'T1', 'unit42', None, 'feed', 'https://unit42.paloaltonetworks.com/feed/', 60),
    ('volexity', 'Volexity', 'T1', 'volexity', None, 'feed', 'https://www.volexity.com/feed/', 60),
    ('watchtowr', 'watchTowr Labs', 'T1', 'watchtowr', None, 'feed', 'https://labs.watchtowr.com/rss/', 60),
    ('wiz', 'Wiz Blog', 'T1', 'wiz', None, 'feed', 'https://www.wiz.io/feed/rss.xml', 60),
    ('aikido', 'Aikido Blog', 'T2', 'aikido', None, 'feed', 'https://www.aikido.dev/blog/rss.xml', 60),
    ('bitdefender', 'Bitdefender Labs', 'T2', 'bitdefender', None, 'feed', 'https://www.bitdefender.com/blog/api/rss/labs/', 60),
    ('cloudflare_sec', 'Cloudflare Blog · Security', 'T2', 'cloudflare_sec', None, 'feed', 'https://blog.cloudflare.com/tag/security/rss/', 60),
    ('crowdstrike', 'CrowdStrike Blog', 'T2', 'crowdstrike', None, 'feed', 'https://www.crowdstrike.com/en-us/blog/feed', 60),
    ('elastic_sl', 'Elastic Security Labs', 'T2', 'elastic_sl', None, 'feed', 'https://www.elastic.co/security-labs/rss/feed.xml', 60),
    ('github_sec', 'GitHub Security Blog', 'T2', 'github_sec', None, 'feed', 'https://github.blog/security/feed/', 60),
    ('horizon3', 'Horizon3.ai', 'T2', 'horizon3', None, 'feed', 'https://www.horizon3.ai/feed/', 60),
    ('malwarebytes', 'Malwarebytes Labs', 'T2', 'malwarebytes', None, 'feed', 'https://www.malwarebytes.com/blog/feed/index.xml', 60),
    ('objective_see', 'Objective-See', 'T2', 'objective_see', None, 'feed', 'https://objective-see.org/rss.xml', 60),
    ('portswigger', 'PortSwigger Research', 'T2', 'portswigger', None, 'feed', 'https://portswigger.net/research/rss', 60),
    ('proofpoint', 'Proofpoint Threat Insight', 'T2', 'proofpoint', None, 'feed', 'https://www.proofpoint.com/us/threat-insight-blog.xml', 60),
    ('rapid7', 'Rapid7 Blog', 'T2', 'rapid7', None, 'feed', 'https://www.rapid7.com/blog/rss/', 60),
    ('recordedfuture', 'Recorded Future', 'T2', 'recordedfuture', None, 'feed', 'https://www.recordedfuture.com/feed', 60),
    ('snyk', 'Snyk Blog', 'T2', 'snyk', None, 'feed', 'https://snyk.io/blog/feed/', 60),
    ('stepsecurity', 'StepSecurity Blog', 'T2', 'stepsecurity', None, 'feed', 'https://www.stepsecurity.io/blog/rss.xml', 60),
    ('tenable', 'Tenable Blog', 'T2', 'tenable', None, 'feed', 'https://www.tenable.com/blog/feed', 60),
    ('tob', 'Trail of Bits', 'T2', 'tob', None, 'feed', 'https://blog.trailofbits.com/feed/', 60),
    ('zdi_blog', 'Zero Day Initiative Blog', 'T2', 'zdi_blog', None, 'feed', 'https://www.zerodayinitiative.com/blog?format=rss', 60),
    # --- vendor
    ('cisco_psirt', 'Cisco PSIRT', 'T1', 'cisco_psirt', 'vuln', 'feed', 'https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml', 15),
    ('gitlab_sec', 'GitLab Security Releases', 'T1', 'gitlab_sec', 'vuln', 'feed', 'https://about.gitlab.com/security-releases.xml', 15),
    ('jenkins', 'Jenkins Security Advisories', 'T1', 'jenkins', 'vuln', 'feed', 'https://www.jenkins.io/security/advisories/rss.xml', 15),
    ('k8s_sec', 'Kubernetes Security Announcements', 'T1', 'k8s_sec', 'vuln', 'feed', 'https://kubernetes.io/docs/reference/issues-security/official-cve-feed/feed.xml', 15),
    ('mozilla', 'Mozilla Security Blog', 'T1', 'mozilla', 'vuln', 'feed', 'https://blog.mozilla.org/security/feed/', 15),
    ('msrc_update', 'MSRC Security Update Guide', 'T1', 'msrc_update', 'vuln', 'feed', 'https://api.msrc.microsoft.com/update-guide/rss', 15),
    ('nodejs_vuln', 'Node.js Vulnerability Blog', 'T1', 'nodejs_vuln', 'vuln', 'feed', 'https://nodejs.org/en/feed/vulnerability.xml', 15),
    ('oracle_cpu', 'Oracle Security Alerts', 'T1', 'oracle_cpu', 'vuln', 'feed', 'https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml', 15),
    ('pan_psirt', 'Palo Alto Networks Advisories', 'T1', 'pan_psirt', 'vuln', 'feed', 'https://security.paloaltonetworks.com/rss.xml', 15),
    ('php', 'PHP Releases', 'T1', 'php', 'vuln', 'feed', 'https://www.php.net/releases/feed.php', 15),
    ('alas2023', 'Amazon Linux 2023 ALAS', 'T3', 'alas2023', 'vuln', 'feed', 'https://alas.aws.amazon.com/AL2023/alas.rss', 15),
    ('debian_dsa', 'Debian Security Advisories', 'T3', 'debian_dsa', 'vuln', 'feed', 'https://www.debian.org/security/dsa-long', 15),
    ('golang', 'Go Blog / Releases', 'T3', 'golang', 'vuln', 'feed', 'https://go.dev/blog/feed.atom', 15),
    ('ubuntu_usn', 'Ubuntu Security Notices', 'T3', 'ubuntu_usn', 'vuln', 'feed', 'https://ubuntu.com/security/notices/rss.xml', 15),
    # --- vuln
    ('cvefeed', 'cvefeed.io', 'T2', 'cvefeed', 'vuln', 'feed', 'https://cvefeed.io/rssfeed/latest.xml', 15),
    ('oss_security', 'oss-security', 'T2', 'oss_security', 'vuln', 'feed', 'https://seclists.org/rss/oss-sec.rss', 15),
    ('sploitus', 'Sploitus', 'T2', 'sploitus', 'vuln', 'feed', 'https://sploitus.com/rss', 15),
    ('exploitdb', 'Exploit-DB', 'T3', 'exploitdb', 'vuln', 'feed', 'https://www.exploit-db.com/rss.xml', 15),
    ('fulldisclosure', 'Full Disclosure', 'T3', 'fulldisclosure', 'vuln', 'feed', 'https://seclists.org/rss/fulldisclosure.rss', 15),
    # --- web3
    ('bitcoinmagazine', 'Bitcoin Magazine', 'T2', 'bitcoinmagazine', None, 'feed', 'https://bitcoinmagazine.com/.rss/full/', 15),
    ('cryptonews', 'Cryptonews', 'T2', 'cryptonews', None, 'feed', 'https://cryptonews.com/news/feed/', 15),
    ('cryptoslate', 'CryptoSlate', 'T2', 'cryptoslate', None, 'feed', 'https://cryptoslate.com/feed/', 15),
    ('dlnews', 'DL News', 'T2', 'dlnews', None, 'feed', 'https://www.dlnews.com/arc/outboundfeeds/rss/', 15),
    ('openzeppelin', 'OpenZeppelin Blog', 'T2', 'openzeppelin', None, 'feed', 'https://blog.openzeppelin.com/rss.xml', 15),
    ('protos', 'Protos', 'T2', 'protos', None, 'feed', 'https://protos.com/feed/', 15),
    ('techflowpost', '深潮 TechFlow', 'T2', 'techflowpost', None, 'feed', 'https://www.techflowpost.com/rss.aspx', 15),
    ('utoday', 'U.Today', 'T2', 'utoday', None, 'feed', 'https://u.today/rss', 15),
    ('zellic', 'Zellic Blog', 'T2', 'zellic', None, 'feed', 'https://www.zellic.io/blog/rss.xml', 15),
    ('beincrypto', 'BeInCrypto', 'T3', 'beincrypto', None, 'feed', 'https://beincrypto.com/feed/', 15),
    ('chaincatcher', 'ChainCatcher 链捕手', 'T3', 'chaincatcher', None, 'feed', 'https://www.chaincatcher.com/rss/clist', 15),
    ('cryptopolitan', 'Cryptopolitan', 'T3', 'cryptopolitan', None, 'feed', 'https://www.cryptopolitan.com/feed/', 15),
    ('unchained', 'Unchained', 'T3', 'unchained', None, 'feed', 'https://unchainedcrypto.com/feed/', 15),
    ('w3igg', 'Web3 is Going Just Great', 'T3', 'w3igg', None, 'feed', 'https://www.web3isgoinggreat.com/feed.xml', 15),
    ('wublock', 'Wu Blockchain', 'T3', 'wublock', None, 'feed', 'https://wublock.substack.com/feed', 15),
)

# exchange announcement boards (CoinMarketCap top-100 rank in the trailing comment)
EXCHANGES: tuple[tuple[str, str, str, str, str | None, str, str, int], ...] = (
    ('ex_coinbase_exchange', 'Coinbase Exchange 状态页', 'T1', 'coinbase_exchange', 'web3', 'feed', 'https://status.coinbase.com/history.rss', 5),  # #2
    ('ex_okx', 'OKX 公告', 'T1', 'okx', 'web3', 'ex_okx', 'https://www.okx.com/api/v5/support/announcements', 5),  # #4
    ('ex_bybit', 'Bybit 公告', 'T1', 'bybit', 'web3', 'ex_bybit', 'https://api.bybit.com/v5/announcements/index?locale=en-US&limit=20', 5),  # #5
    ('ex_bitget', 'Bitget 公告', 'T1', 'bitget', 'web3', 'ex_bitget', 'https://api.bitget.com/api/v2/public/annoucements?language=en_US', 5),  # #6
    ('ex_kucoin', 'KuCoin 公告', 'T1', 'kucoin', 'web3', 'ex_kucoin', 'https://api.kucoin.com/api/v3/announcements?lang=en_US&pageSize=20', 5),  # #8
    ('ex_mexc', 'MEXC 公告', 'T1', 'mexc', 'web3', 'ex_mexc', 'https://www.mexc.com/help/announce/api/en-US/section/360000254192/articles?page=1&perPage=20', 5),  # #9
    ('ex_htx', 'HTX 公告', 'T1', 'htx', 'web3', 'ex_htx', 'https://www.htx.com/-/x/support/public/getList/v2?page=1&limit=20&oneLevelId=360000031902&twoLevelId=360000039942&language=en-us', 5),  # #10
    ('ex_crypto_com_exchange', 'Crypto.com Exchange 公告', 'T1', 'crypto_com_exchange', 'web3', 'ex_crypto_com_exchange', 'https://api.crypto.com/v1/public/get-announcements?category=list', 5),  # #11
    ('ex_kraken', 'Kraken 状态页', 'T1', 'kraken', 'web3', 'feed', 'https://status.kraken.com/history.rss', 5),  # #14
    ('ex_bitstamp', 'Bitstamp by Robinhood 状态页', 'T1', 'bitstamp', 'web3', 'feed', 'https://status.bitstamp.net/history.rss', 5),  # #17
    ('ex_bithumb', 'Bithumb 公告', 'T1', 'bithumb', 'web3', 'ex_bithumb', 'https://feed-api.bithumb.com/v1/notices', 5),  # #18
    ('ex_xt', 'XT.COM 公告', 'T1', 'xt', 'web3', 'zendesk', 'https://xtsupport.zendesk.com/api/v2/help_center/en-us/articles.json?sort_by=created_at&sort_order=desc&per_page=10', 5),  # #19
    ('ex_tokocrypto', 'Tokocrypto 公告', 'T1', 'tokocrypto', 'web3', 'zendesk', 'https://support.tokocrypto.com/api/v2/help_center/en-us/categories/360003086532/articles.json?sort_by=created_at&sort_order=desc&per_page=10', 5),  # #20
    ('ex_gemini', 'Gemini 状态页', 'T1', 'gemini', 'web3', 'feed', 'https://status.gemini.com/history.rss', 10),  # #23
    ('ex_ourbit', 'Ourbit 公告', 'T1', 'ourbit', 'web3', 'ex_ourbit', 'https://www.ourbit.com/help/announce/api/en-US/section/360000254192/articles?page=1&perPage=10', 10),  # #26
    ('ex_biconomy', 'Biconomy.com 公告', 'T1', 'biconomy', 'web3', 'zendesk', 'https://biconomy.zendesk.com/api/v2/help_center/en-us/articles.json?sort_by=created_at&sort_order=desc&per_page=10', 10),  # #31
    ('ex_mgbx', 'MGBX 公告', 'T1', 'mgbx', 'web3', 'zendesk', 'https://support.mgbx.com/api/v2/help_center/en-gb/articles.json?sort_by=created_at&sort_order=desc&per_page=10', 10),  # #34
    ('ex_bitunix', 'Bitunix 公告', 'T1', 'bitunix', 'web3', 'zendesk', 'https://support.bitunix.com/api/v2/help_center/en-us/categories/13760946490649/articles.json?sort_by=created_at&sort_order=desc&per_page=10', 10),  # #35
    ('ex_bigone', 'BigONE 公告', 'T1', 'bigone', 'web3', 'zendesk', 'https://bigone.zendesk.com/api/v2/help_center/en-us/articles.json?sort_by=created_at&sort_order=desc&per_page=10', 10),  # #36
    ('ex_echobit', 'Echobit 公告', 'T1', 'echobit', 'web3', 'zendesk', 'https://support.echobit.com/api/v2/help_center/en-us/sections/42139947783577/articles.json?sort_by=created_at&sort_order=desc&per_page=10', 10),  # #37
    ('ex_hibt', 'Hibt 公告', 'T1', 'hibt', 'web3', 'zendesk', 'https://support.hibt.com/api/v2/help_center/en-us/articles.json?sort_by=created_at&sort_order=desc&per_page=10', 10),  # #39
    ('ex_btse', 'BTSE 公告', 'T1', 'btse', 'web3', 'feed', 'https://www.btse.com/blog/category/announcements/feed/', 10),  # #42
    ('ex_bitvavo', 'Bitvavo 公告', 'T1', 'bitvavo', 'web3', 'zendesk', 'https://support.bitvavo.com/api/v2/help_center/en-us/articles.json?sort_by=created_at&sort_order=desc&per_page=10', 10),  # #43
    ('ex_bifinance_exchange', 'BiFinance 公告', 'T1', 'bifinance_exchange', 'web3', 'zendesk', 'https://bifinance.zendesk.com/api/v2/help_center/en-001/articles.json?sort_by=created_at&sort_order=desc&per_page=10', 10),  # #44
    ('ex_tapbit', 'Tapbit 公告', 'T1', 'tapbit', 'web3', 'zendesk', 'https://tapbitcex.zendesk.com/api/v2/help_center/en-us/categories/12190685604367/articles.json?sort_by=created_at&sort_order=desc&per_page=10', 10),  # #49
    ('ex_hashkey_global', 'HashKey Global 公告', 'T1', 'hashkey_global', 'web3', 'zendesk', 'https://help.hashkey.com/api/v2/help_center/en-us/sections/26776421550236/articles.json?sort_by=created_at&sort_order=desc', 10),  # #54
    ('ex_zaif', 'Zaif 公告', 'T1', 'zaif', 'web3', 'feed', 'https://corp.zaif.jp/info/rss.xml', 10),  # #55
    ('ex_bitrue', 'Bitrue 公告', 'T1', 'bitrue', 'web3', 'zendesk', 'https://support.bitrue.com/api/v2/help_center/en-001/articles.json?sort_by=created_at&sort_order=desc', 10),  # #59
    ('ex_bitbase_com', 'Bitbase 公告', 'T1', 'bitbase_com', 'web3', 'zendesk', 'https://bitbase-support.zendesk.com/api/v2/help_center/en-us/articles.json?sort_by=created_at&sort_order=desc', 10),  # #60
    ('ex_crypfine', 'CrypFine 公告', 'T1', 'crypfine', 'web3', 'zendesk', 'https://crypfine.zendesk.com/api/v2/help_center/en-001/articles.json?sort_by=created_at&sort_order=desc', 10),  # #61
    ('ex_bitso', 'Bitso 状态页', 'T1', 'bitso', 'web3', 'feed', 'https://status.bitso.com/history.rss', 10),  # #64
    ('ex_luno', 'Luno 公告', 'T1', 'luno', 'web3', 'zendesk', 'https://guide.luno.com/api/v2/help_center/en-gb/sections/40118100728093/articles.json?sort_by=created_at&sort_order=desc', 10),  # #66
    ('ex_hashkey_exchange', 'HashKey Exchange 公告', 'T1', 'hashkey_exchange', 'web3', 'zendesk', 'https://support.hashkey.com/api/v2/help_center/en-gb/sections/900000539746/articles.json?sort_by=created_at&sort_order=desc', 10),  # #67
    ('ex_voox_exchange', 'x.me Exchange 公告', 'T1', 'voox_exchange', 'web3', 'zendesk', 'https://support.x.me/api/v2/help_center/en-us/articles.json?sort_by=created_at&sort_order=desc', 10),  # #74
    ('ex_bit2me', 'Bit2Me 状态页', 'T1', 'bit2me', 'web3', 'feed', 'https://status.bit2me.com/history.rss', 10),  # #75
    ('ex_bittrade', 'BitTrade 公告', 'T1', 'bittrade', 'web3', 'zendesk', 'https://support.bittrade.co.jp/api/v2/help_center/ja/sections/360005156653/articles.json?sort_by=created_at&sort_order=desc&per_page=30', 10),  # #82
    ('ex_woox', 'WOO X 公告', 'T1', 'woox', 'web3', 'zendesk', 'https://support.woox.io/api/v2/help_center/en-us/sections/4403604368025/articles.json?sort_by=created_at&sort_order=desc&per_page=30', 10),  # #87
    ('ex_astralx', 'AstralX 公告', 'T1', 'astralx', 'web3', 'zendesk', 'https://support.astralx.com/api/v2/help_center/en-001/articles.json?sort_by=created_at&sort_order=desc&per_page=30', 10),  # #89
    ('ex_bullish', 'Bullish 状态页', 'T1', 'bullish', 'web3', 'feed', 'https://status.bullish.com/history.rss', 10),  # #91
    ('ex_foxbit', 'Foxbit 公告', 'T1', 'foxbit', 'web3', 'zendesk', 'https://faq.foxbit.com.br/api/v2/help_center/pt-br/articles.json?sort_by=created_at&sort_order=desc&per_page=30', 10),  # #92
    ('ex_rekeningku_com', 'Reku 公告', 'T1', 'rekeningku_com', 'web3', 'feed', 'https://api-blog.reku.id/feed/', 10),  # #93
)

# Telegram public channels (t.me/s web preview, parser telegram) and WeChat official accounts via Wechat2RSS
# (docs/research/18): admitted by scripts/source-onboard.py from the radar's egress 2026-11-10 (46/46 ok). A channel
# of an outlet already collected by RSS keeps that outlet's org — the two are one source, not two independent ones.
# WeChat feeds are full text (1–7 MB): 120-minute cadence; they bring analysis and reproduction notices, not scoops.
SOCIAL: tuple[tuple[str, str, str, str, str | None, str, str, int], ...] = (
    # --- telegram
    ("tg_zachxbt", "ZachXBT Investigations (TG)", "T1", "zachxbt", "web3", "telegram", "https://t.me/s/investigations", 5),
    ("tg_wublock", "吴说区块链 (TG)", "T2", "wublock", None, "telegram", "https://t.me/s/wublock", 5),
    ("tg_wublock_en", "Wu Blockchain (TG)", "T2", "wublock", None, "telegram", "https://t.me/s/wublockchainenglish", 5),
    ("tg_bwenews", "方程式新闻 BWEnews (TG)", "T2", "bwenews", None, "telegram", "https://t.me/s/BWEnews", 5),
    ("tg_vxunderground", "vx-underground (TG)", "T2", "vxunderground", None, "telegram", "https://t.me/s/vxunderground", 10),
    ("tg_ransomlook", "RansomLook (TG)", "T3", "ransomlook", "incident", "telegram", "https://t.me/s/RansomLook", 10),
    ("tg_hackmanac", "Hackmanac Cyber News (TG)", "T3", "hackmanac", None, "telegram", "https://t.me/s/hackmanac_cybernews", 10),
    ("tg_blockbeats", "BlockBeats (TG)", "T3", "blockbeats", None, "telegram", "https://t.me/s/theblockbeats", 5),
    ("tg_odaily", "Odaily (TG)", "T3", "odaily", None, "telegram", "https://t.me/s/odaily_news", 5),
    ("tg_foresight", "Foresight News (TG)", "T3", "foresight", None, "telegram", "https://t.me/s/foresightnews", 5),
    ("tg_panews", "PANews (TG)", "T3", "panews", None, "telegram", "https://t.me/s/ChannelPANews", 5),
    ("tg_techflow", "深潮 TechFlow (TG)", "T3", "techflowpost", None, "telegram", "https://t.me/s/TechFlowDaily", 5),
    ("tg_chaincatcher", "链捕手 (TG)", "T3", "chaincatcher", None, "telegram", "https://t.me/s/chaincatcher", 5),
    ("tg_jinse", "金色财经 (TG)", "T3", "jinse", None, "telegram", "https://t.me/s/jinse2017", 10),
    ("tg_abmedia", "鏈新聞 ABMedia (TG)", "T3", "abmedia", None, "telegram", "https://t.me/s/abmedia_news", 10),
    ("tg_cointelegraph", "Cointelegraph (TG)", "T3", "cointelegraph", None, "telegram", "https://t.me/s/Cointelegraph", 10),
    ("tg_lookonchain", "Lookonchain (TG)", "T3", "lookonchain", "web3", "telegram", "https://t.me/s/lookonchainchannel", 5),
    ("tg_thehackernews", "The Hacker News (TG)", "T3", "thehackernews", None, "telegram", "https://t.me/s/thehackernews", 10),
    ("tg_bleepingcomputer", "BleepingComputer (TG)", "T3", "bleepingcomputer", None, "telegram", "https://t.me/s/bleepingcomputer", 10),
    ("tg_malwr", "Malware News (TG)", "T3", "malwr", None, "telegram", "https://t.me/s/malwr", 15),
    ("tg_topcyber", "Latest Cyber-Attack News (TG)", "T3", "topcybersecurity", None, "telegram", "https://t.me/s/topcybersecurity", 15),
    # --- WeChat official accounts (Wechat2RSS public feeds)
    ("wx_slowmist", "慢雾科技 (公众号)", "T1", "slowmist", "web3", "feed", "https://wechat2rss.xlab.app/feed/9e9c3c70e598266a1ac993e50458a10a6d853eb7.xml", 120),
    ("wx_qianxin_ti", "奇安信威胁情报中心 (公众号)", "T1", "qianxin", None, "feed", "https://wechat2rss.xlab.app/feed/b93962f981247c0091dad08df5b7a6864ab888e9.xml", 120),
    ("wx_qianxin_cert", "奇安信CERT (公众号)", "T1", "qianxin", "vuln", "feed", "https://wechat2rss.xlab.app/feed/981c000a01bbdc1f128d260cc91c15d3a6afb530.xml", 120),
    ("wx_qianxin_xlab", "奇安信XLab (公众号)", "T1", "qianxin", None, "feed", "https://wechat2rss.xlab.app/feed/5c7b6eec254fbb0afac7abf4eae95573fc374555.xml", 120),
    ("wx_threatbook", "微步在线研究响应中心 (公众号)", "T1", "threatbook", None, "feed", "https://wechat2rss.xlab.app/feed/ac64c385ebcdb17fee8df733eb620a22b979928c.xml", 120),
    ("wx_secrss", "互联网安全内参 (公众号)", "T2", "secrss", None, "feed", "https://wechat2rss.xlab.app/feed/d5eb8577bf93aacdd7481ad0c3364939096b99a1.xml", 120),
    ("wx_xuanwu", "腾讯玄武实验室 (公众号)", "T1", "tencent", None, "feed", "https://wechat2rss.xlab.app/feed/923c0e2f33b6d39c8a826a90f185725f0edb10e8.xml", 120),
    ("wx_keen", "腾讯科恩实验室 (公众号)", "T1", "tencent", None, "feed", "https://wechat2rss.xlab.app/feed/13584cb01e8bf3297943a0dad49e53c6faf20611.xml", 120),
    ("wx_tencent_ti", "腾讯安全威胁情报中心 (公众号)", "T1", "tencent", None, "feed", "https://wechat2rss.xlab.app/feed/034265b14906a59ef7cf1fcbd56699b54a696094.xml", 120),
    ("wx_tsrc", "腾讯安全应急响应中心 (公众号)", "T1", "tencent", "vuln", "feed", "https://wechat2rss.xlab.app/feed/7898375f78fd1018302d54577cd0fd05d5ed324f.xml", 120),
    ("wx_aliyun_er", "阿里云应急响应 (公众号)", "T1", "aliyun", "vuln", "feed", "https://wechat2rss.xlab.app/feed/311c02e5c56e5c0bcdf41924909407ed2d569d2a.xml", 120),
    ("wx_nsfocus_cert", "绿盟科技CERT (公众号)", "T1", "nsfocus", "vuln", "feed", "https://wechat2rss.xlab.app/feed/aa2ff3b0167a3f449f3b116717b5350ab64df8c3.xml", 120),
    ("wx_sangfor", "深信服千里目安全实验室 (公众号)", "T1", "sangfor", None, "feed", "https://wechat2rss.xlab.app/feed/027c7f3b98d9d0f2db84513f0cb94f02e9a8a3d7.xml", 120),
    ("wx_360_sec", "360数字安全 (公众号)", "T2", "qihoo360", None, "feed", "https://wechat2rss.xlab.app/feed/85e7bf4fe192ded1a15f130aa43ac306d227f61b.xml", 120),
    ("wx_360_ti", "360威胁情报中心 (公众号)", "T1", "qihoo360", None, "feed", "https://wechat2rss.xlab.app/feed/920f171e3dae0c8eeb4c97b366b229ba19807732.xml", 120),
    ("wx_360_vuln", "360漏洞云 (公众号)", "T2", "qihoo360", "vuln", "feed", "https://wechat2rss.xlab.app/feed/ca1fddd8505a3473feed12c0bee898e97d4d5eae.xml", 120),
    ("wx_chaitin", "长亭科技 (公众号)", "T2", "chaitin", None, "feed", "https://wechat2rss.xlab.app/feed/2b3d1f9d72a621232894fa96b6ddf218aade7a1f.xml", 120),
    ("wx_seebug", "Seebug漏洞平台 (公众号)", "T2", "seebug", "vuln", "feed", "https://wechat2rss.xlab.app/feed/be2795d741304af2370cbf8d31d1e5d3675f8e85.xml", 120),
    ("wx_anquanke", "安全客 (公众号)", "T2", "anquanke", None, "feed", "https://wechat2rss.xlab.app/feed/7fc9f5344f14228ba49208282d844349f8afdee7.xml", 120),
    ("wx_cnvd", "CNVD漏洞平台 (公众号)", "T1", "cnvd", "vuln", "feed", "https://wechat2rss.xlab.app/feed/edf17c7a01a7152b7a1ca14133258dc4abc1ca61.xml", 120),
    ("wx_kanxue", "看雪学院 (公众号)", "T2", "kanxue", None, "feed", "https://wechat2rss.xlab.app/feed/0e026637254d450ae84c59f87d4e4fb4616651ca.xml", 120),
    ("wx_huorong", "火绒安全实验室 (公众号)", "T2", "huorong", None, "feed", "https://wechat2rss.xlab.app/feed/e6da68c95a8f1e2fb40f6691d0ce9addc51a7532.xml", 120),
    ("wx_yazx", "永安在线情报平台 (公众号)", "T2", "yazx", None, "feed", "https://wechat2rss.xlab.app/feed/9f7e55c77c8eaf5f2adb43289de4fe194f7d34e5.xml", 120),
    ("wx_butian", "补天平台 (公众号)", "T3", "butian", None, "feed", "https://wechat2rss.xlab.app/feed/716b21d89522f8bb90b25249ebf00692522d5612.xml", 120),
    ("doonsec", "洞见网安 (公众号聚合)", "T3", "doonsec", None, "feed_cst", "https://wechat.doonsec.com/rss.xml", 60),
)
