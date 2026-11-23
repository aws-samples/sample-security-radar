"""P0 classification wall (Neo 2026-11-22): every P0 belongs to a PRODUCT tile, tiles sit in GROUPS. One taxonomy, in
code — radar.cloudstack's 「is it a cloud component」 is the group's `cloud` flag, never a second list.

The product the TITLE names first wins (titles lead with the affected product: 「Cisco … Java」 is Cisco); the entities are
read only when the title names no registered product. A language
named as a flaw class (「PHP Object Injection」) is removed before matching. An unregistered product still gets its own
tile in OTHER, named from the event's first entity (the CVE record's vendor) — nothing falls off the wall."""
from __future__ import annotations

import re
from dataclasses import dataclass

_CLASS = re.compile(r"(?i)\bphp\s+(?:object\s+injection|code\s+injection|file\s+inclusion|remote\s+file\s+inclusion)\b")


@dataclass(frozen=True)
class Group:
    id: str
    label: str
    cloud: bool           # mainstream cloud components (the team channel's prefilter)


@dataclass(frozen=True)
class Product:
    id: str
    label: str
    group: str
    pattern: str          # case-insensitive, letter-bounded

    def find(self, text: str) -> int:
        """Where the product is first named in `text` (-1: not named)."""
        m = re.search(rf"(?i)(?<![a-z0-9])(?:{self.pattern})(?![a-z])", text)
        return m.start() if m else -1

    def matches(self, text: str) -> bool:
        return self.find(text) >= 0


GROUPS: tuple[Group, ...] = (
    Group("web", "Web 服务器与网关", True), Group("framework", "Web 框架与 Java 中间件", True),
    Group("runtime", "编程语言与运行时", True), Group("database", "数据库与消息中间件", True),
    Group("container", "容器、云原生与 CI/CD", True), Group("ai", "AI 推理与开发", True),
    Group("web3", "Web3 节点与工具链", True), Group("os", "操作系统与基础库", True),
    Group("cms", "CMS 与插件", False), Group("appliance", "网络与安全设备", False),
    Group("endpoint", "终端、浏览器与办公", False), Group("enterprise", "企业应用与虚拟化", False),
    Group("ics", "工控与物联网", False), Group("other", "其他", False),
)
GROUP = {g.id: g for g in GROUPS}

_P = Product
PRODUCTS: tuple[Product, ...] = (
    # ---- not cloud first: these names often contain a generic word (Java, PHP, Apache …)
    _P("wordpress", "WordPress", "cms", r"wordpress|wp\s+plugin|woocommerce|buddypress|buddyboss|elementor|masteriyo|"
       r"newsletters?\s+plugin|[\w-]+\s+plugin\s+(?:<=|<|before)"),
    _P("drupal", "Drupal", "cms", r"drupal"), _P("joomla", "Joomla", "cms", r"joomla"),
    _P("magento", "Magento", "cms", r"magento|adobe\s+commerce"),
    _P("cisco", "Cisco", "appliance", r"cisco"), _P("fortinet", "Fortinet", "appliance", r"fortinet|forti\w+"),
    _P("paloalto", "Palo Alto", "appliance", r"pan-os|palo\s+alto|globalprotect"),
    _P("sonicwall", "SonicWall", "appliance", r"sonicwall|sonicos"), _P("citrix", "Citrix", "appliance", r"citrix|netscaler"),
    _P("ivanti", "Ivanti", "appliance", r"ivanti|pulse\s+secure"), _P("f5bigip", "F5 BIG-IP", "appliance", r"big-?ip"),
    _P("juniper", "Juniper", "appliance", r"juniper|junos"), _P("barracuda", "Barracuda", "appliance", r"barracuda"),
    _P("checkpoint", "Check Point", "appliance", r"check\s+point"),
    _P("soho", "路由器 / NAS", "appliance", r"d-link|tp-link|netgear|zyxel|mikrotik|ubiquiti|draytek|qnap|synology|asus\s+router"),
    _P("windows", "Windows", "endpoint", r"windows|signdrop|fastunlock"),
    _P("office", "Microsoft Office", "endpoint", r"microsoft\s+(?:office|outlook|word|excel|teams)|outlook"),
    _P("exchange", "Exchange / SharePoint", "endpoint", r"exchange\s+server|sharepoint"),
    _P("chrome", "Chrome / Chromium", "endpoint", r"chrome|chromium"), _P("safari", "Safari / WebKit", "endpoint", r"safari|webkit"),
    _P("firefox", "Firefox", "endpoint", r"firefox|thunderbird"),
    _P("apple", "Apple iOS / macOS", "endpoint", r"ios|ipados|iphone|macos|apple"),
    _P("android", "Android", "endpoint", r"android|pixel"), _P("whatsapp", "WhatsApp", "endpoint", r"whatsapp"),
    _P("archiver", "7-Zip / WinRAR", "endpoint", r"7-zip|winrar"), _P("adobe", "Adobe", "endpoint", r"adobe|acrobat"),
    _P("sap", "SAP", "enterprise", r"sap|netweaver"),
    _P("oracleapps", "Oracle 企业应用", "enterprise", r"oracle\s+(?:e-?business|ebs|peoplesoft|siebel|fusion)|ebs\s+vulnerab"),
    _P("vmware", "VMware vCenter / ESXi", "enterprise", r"vmware|vcenter|esxi|vsphere"),
    _P("atlassian", "Atlassian", "enterprise", r"atlassian|confluence|jira|bitbucket"),
    _P("jetbrains", "JetBrains TeamCity", "enterprise", r"teamcity|jetbrains"),
    _P("rmm", "远程运维 (ScreenConnect 等)", "enterprise", r"connectwise|screenconnect|n-able|n-central|solarwinds|"
       r"manageengine|kaseya|anydesk|teamviewer"),
    _P("filetransfer", "文件传输 (MOVEit 等)", "enterprise", r"moveit|goanywhere|crushftp|cleo"),
    _P("backup", "备份 (Veeam 等)", "enterprise", r"veeam|commvault|veritas"),
    _P("siemens", "Siemens", "ics", r"siemens|simatic"), _P("ics", "工控 / SCADA", "ics", r"scada|schneider|rockwell|honeywell|"
       r"mitsubishi\s+electric|abb\s|plc|icsa-\d|va-\d|unstable\s+slope"),
    # ---- cloud components
    _P("geth", "Geth / 以太坊客户端", "web3", r"geth|go-ethereum|erigon|nethermind|besu|reth|lighthouse|prysm"),
    _P("solana", "Solana", "web3", r"solana|agave|anza|anchor"),
    _P("evmtools", "合约工具链 (OpenZeppelin 等)", "web3", r"openzeppelin|solidity|vyper|hardhat|foundry"),
    _P("web3js", "Web3 客户端库", "web3", r"ethers\.?js|web3\.?js|viem|wagmi"),
    _P("cosmos", "Cosmos / Substrate", "web3", r"cosmos\s+sdk|cometbft|tendermint|substrate|polkadot"),
    _P("vllm", "vLLM", "ai", r"vllm"), _P("sglang", "SGLang", "ai", r"sglang"), _P("ollama", "Ollama", "ai", r"ollama"),
    _P("langchain", "LangChain / LlamaIndex", "ai", r"langchain|llamaindex|llama_index"),
    _P("jupyter", "Jupyter", "ai", r"jupyter"), _P("mlplatform", "ML 平台 (MLflow / Ray 等)", "ai", r"mlflow|ray|kubeflow|triton"),
    _P("aiui", "AI 应用 (Open WebUI / ComfyUI 等)", "ai", r"open\s*webui|comfyui|litellm|dify|flowise"),
    _P("kubernetes", "Kubernetes", "container", r"kubernetes|k8s|kubelet|kube-\w+"), _P("docker", "Docker", "container", r"docker"),
    _P("containerd", "containerd / runc", "container", r"containerd|runc"), _P("helm", "Helm / Argo CD", "container", r"helm|argo\s*cd"),
    _P("istio", "Istio", "container", r"istio"), _P("gitlab", "GitLab", "container", r"gitlab"),
    _P("jenkins", "Jenkins", "container", r"jenkins"), _P("github", "GitHub Actions", "container", r"github\s+actions"),
    _P("hashicorp", "HashiCorp (Terraform / Vault)", "container", r"terraform|hashicorp|vault\s+server|consul|nomad"),
    _P("observability", "Grafana / Prometheus", "container", r"grafana|prometheus|loki"),
    _P("keycloak", "Keycloak", "container", r"keycloak"), _P("minio", "MinIO / Harbor", "container", r"minio|harbor"),
    _P("mysql", "MySQL / MariaDB", "database", r"mysql|mariadb"), _P("postgres", "PostgreSQL", "database", r"postgres(?:ql)?"),
    _P("redis", "Redis / Valkey", "database", r"redis|valkey"), _P("mongodb", "MongoDB", "database", r"mongodb"),
    _P("elastic", "Elasticsearch / OpenSearch", "database", r"elasticsearch|opensearch|kibana"),
    _P("kafka", "Kafka", "database", r"kafka"), _P("mq", "RabbitMQ / ActiveMQ", "database", r"rabbitmq|activemq"),
    _P("mqtt", "MQTT (Mosquitto 等)", "database", r"mosquitto|mqtt|emqx"),
    _P("dbother", "其他数据库 (ClickHouse 等)", "database", r"clickhouse|cassandra|memcached|etcd|zookeeper|nacos|couchdb"),
    _P("nginx", "Nginx", "web", r"nginx|openresty"), _P("apache", "Apache HTTP Server", "web", r"apache\s+(?:http|httpd)|httpd"),
    _P("tomcat", "Tomcat", "web", r"tomcat"), _P("proxy", "Envoy / HAProxy / Traefik", "web", r"envoy|haproxy|traefik|caddy|"
       r"varnish|squid"),
    _P("spring", "Spring", "framework", r"spring(?:\s+(?:boot|framework|cloud|security))?"),
    _P("struts", "Struts", "framework", r"struts"), _P("javaee", "WebLogic / JBoss", "framework", r"weblogic|websphere|jboss|wildfly"),
    _P("jsframework", "前端 / Node 框架 (Next.js 等)", "framework", r"next\.?js|react|vue|angular|express|nuxt|svelte"),
    _P("pyframework", "Python 框架 (Django 等)", "framework", r"django|flask|fastapi"),
    _P("phpframework", "PHP 框架 (Laravel 等)", "framework", r"laravel|symfony"),
    _P("rails", "Ruby on Rails", "framework", r"rails"),
    _P("kernel", "Linux 内核", "os", r"linux(?:\s+kernel)?|kernel"), _P("openssl", "OpenSSL", "os", r"openssl|libssl"),
    _P("openssh", "OpenSSH", "os", r"openssh"), _P("glibc", "glibc", "os", r"glibc"),
    _P("oscore", "系统组件 (sudo / systemd 等)", "os", r"sudo|systemd|polkit|xz|libxml2|curl|bash"),
    _P("distro", "Linux 发行版", "os", r"amazon\s+linux|ubuntu|debian|red\s*hat|rhel"),
    _P("java", "Java / OpenJDK", "runtime", r"openjdk|java|jdk|jre|jvm|log4j|jackson|fastjson"),
    _P("php", "PHP", "runtime", r"php\w*"), _P("python", "Python", "runtime", r"python|pip"),
    _P("node", "Node.js", "runtime", r"node\.?js|npm"), _P("ruby", "Ruby", "runtime", r"ruby"),
    _P("go", "Go", "runtime", r"golang|go\s+(?:standard\s+library|stdlib|runtime|toolchain|compiler|net/http|crypto/\w+)"),
    _P("rust", "Rust", "runtime", r"rust|rustls|tokio"), _P("dotnet", ".NET", "runtime", r"\.net(?:\s+core)?|asp\.net"),
    # last: any other Apache Software Foundation project (Axis, Roller, Solr …); the named ones above keep their tiles
    _P("apacheproj", "Apache 其他项目", "framework", r"apache"),
)
PRODUCT = {p.id: p for p in PRODUCTS}
FALLBACK = frozenset({"apacheproj"})     # only when no other product is named (「Apache Log4j」 is Java, not 「Apache 其他」)


def _first_named(text: str) -> Product | None:
    """The product named FIRST in the text — a title leads with the affected product (「JetBrains TeamCity VMware vSphere
    Cloud Profiles plugin」 is TeamCity); registry order breaks a tie; a fallback product only when nothing else is named."""
    hits = [(at, i, p) for i, p in enumerate(PRODUCTS) if p.id not in FALLBACK and (at := p.find(text)) >= 0]
    if hits:
        return min(hits, key=lambda h: (h[0], h[1]))[2]
    return next((p for p in PRODUCTS if p.id in FALLBACK and p.matches(text)), None)


@dataclass(frozen=True)
class Placement:
    product: str          # product id ("x-<slug>" for an unregistered product)
    label: str
    group: str

    @property
    def cloud(self) -> bool:
        return GROUP[self.group].cloud


_SLUG = re.compile(r"[^a-z0-9]+")
_ID = re.compile(r"^\s*(?:(?:CVE-\d{4}-\d+|GHSA(?:-[a-z0-9]{4}){3}|ICSA-[\d-]+|VA-[\d-]+)\s*[-–:]?\s*)+", re.IGNORECASE)
_AKA = re.compile(r"\(aka\s+([^)]{2,40})\)", re.IGNORECASE)
_GENERIC = re.compile(r"(?i)^(?:a|an|the|critical|high|multiple|new|unauthenticated|authenticated|remote|pre-auth|rce|sqli|xss|"
                      r"ssrf|xxe|lfi|code|command|sql|arbitrary|stored|reflected|vulnerability|vulnerabilities|flaw|bug|"
                      r"exploit|injection|execution|bypass|overflow|missing|improper|use-after-free)$")
_STOP = re.compile(r"(?i)^(?:<=?|before|from|through|prior|up|versions?|v?\d[\w.]*|-|–|is|are|has|allows?|could|via|vulnerab\w*|"
                   r"in|to|and|with|for|on)$")


def _title_name(title: str) -> str:
    """The product a title leads with: 「Daptin: …」 → Daptin, 「OwnTracks Recorder before 1.0.5 …」 → OwnTracks Recorder,
    「monailabel (aka MONAI Label) …」 → MONAI Label, 「RCE in TEGSOFT Management's Tegsoft Contact Center」 → Tegsoft Contact
    Center. A flaw word is never a name (「RCE」 was a tile before this, 2026-11-22 trial)."""
    t = _CLASS.sub(" ", _ID.sub("", title or "")).strip()          # 「PHP Object Injection in Acme Forms」 → Acme Forms
    if m := _AKA.search(t):
        return m.group(1).strip()
    if (m := re.match(r"([^:<>()]{2,40}?):\s", t)) and not _GENERIC.match(m.group(1).split()[0]):
        words = m.group(1).split()
    else:
        words = t.split()
        while words and _GENERIC.match(words[0]):     # 「Critical RCE in X」 → X
            words = words[1:]
        if words and words[0].lower() == "in":
            words = words[1:]
        if any(w.endswith("'s") for w in words[:4]):  # 「TEGSOFT Management's Tegsoft …」 → Tegsoft …
            words = words[next(i for i, w in enumerate(words) if w.endswith("'s")) + 1:]
        out = []
        for w in words:
            if _STOP.match(w) or _GENERIC.match(w) or len(out) == 3:
                break
            out.append(w)
        words = out
    seen: list[str] = []
    for w in words:                                   # 「UnrealIRCd UnrealIRCd」 → UnrealIRCd
        if w.lower() not in (x.lower() for x in seen):
            seen.append(w.strip(",.;"))
    return " ".join(seen)[:40]


def place(title: str, entities: list[str] | None = None) -> Placement:
    """The tile of the affected product. The TITLE decides first (it names the affected product; the entities can carry a
    product that is only mentioned — 「Apache HTTP Server … VMware」 was VMware); entities only when the title names no
    registered product. Unregistered: its own tile in OTHER, named from the title, else from the first entity (the CVE
    record's vendor slug); 「Unknown」 only when there is neither."""
    title_text = _CLASS.sub(" ", _ID.sub("", title or ""))       # 「ICSA-26-237-03 Siemens …」 is Siemens, not the ID
    all_text = _CLASS.sub(" ", " ".join([title or "", *(entities or [])]))
    p = _first_named(title_text) or _first_named(all_text)
    if p:
        return Placement(p.id, p.label, p.group)
    name = _title_name(title) or next((e for e in entities or [] if e and len(e) <= 40), "")
    slug = _SLUG.sub("-", name.lower()).strip("-")[:40]
    return Placement(f"x-{slug}" if slug else "x-unknown", name or "Unknown", "other")
