"""M3 · Amazon Inspector as the dependency judge (D-class: deterministic, no LLM).

P0 measurement (2026-10-29): Inspector ScanSbom judges LANGUAGE packages only — pkg:generic/php, pkg:generic/node,
WordPress and Debian purls returned 0 findings, pypi/npm returned the known CVEs. So the radar keeps judging runtime
pins itself (radar.products) and asks Inspector about what it is authoritative for: the packages in lockfiles.

  sbom(files)        lockfiles in a target → CycloneDX 1.5 (one component per exact package version)
  findings(result)   ScanSbom CycloneDX answer → [{id, severity, purl, fixed}] (sorted, deduplicated)
  for_event(...)     the event's CVEs ∩ a target's Inspector findings — "Inspector says this target is affected"

Inputs are the target zips the respond station already reads (no new copy of the code)."""

from __future__ import annotations

import json
import re
import tomllib
from typing import Any

SEVERITY_ORDER = ("critical", "high", "medium", "low", "none", "unknown")


def _purl(kind: str, name: str, version: str) -> str:
    return f"pkg:{kind}/{name.replace('@', '%40')}@{version}"


def _uv_lock(text: str) -> list[tuple[str, str, str]]:
    return [("pypi", p["name"], p["version"]) for p in tomllib.loads(text).get("package") or []
            if "version" in p and (p.get("source") or {}).get("editable") is None and "virtual" not in (p.get("source") or {})]


def _package_lock(text: str) -> list[tuple[str, str, str]]:
    d = json.loads(text)
    out = [("npm", k.split("node_modules/")[-1], v["version"]) for k, v in (d.get("packages") or {}).items()
           if k.startswith("node_modules/") and v.get("version") and not v.get("link")]
    return out


_EXACT = re.compile(r"^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$")


def _package_json(text: str) -> list[tuple[str, str, str]]:
    """Only exactly pinned versions — a range ("^4.21.2") is not a version Inspector can judge."""
    d = json.loads(text)
    deps = {**(d.get("dependencies") or {}), **(d.get("devDependencies") or {})}
    return [("npm", n, v) for n, v in sorted(deps.items()) if isinstance(v, str) and _EXACT.match(v)]


def _composer_lock(text: str) -> list[tuple[str, str, str]]:
    d = json.loads(text)
    return [("composer", p["name"], p["version"].lstrip("v")) for p in (d.get("packages") or []) + (d.get("packages-dev") or [])
            if p.get("name") and p.get("version")]


def _requirements(text: str) -> list[tuple[str, str, str]]:
    return [("pypi", m.group(1), m.group(2)) for m in re.finditer(r"(?m)^\s*([A-Za-z0-9_.-]+)\s*==\s*([0-9][^\s;#]*)", text)]


# basename → reader. A lockfile beats its manifest: package.json is read only where no package-lock.json sits next to it.
READERS = {"uv.lock": _uv_lock, "package-lock.json": _package_lock, "composer.lock": _composer_lock,
           "requirements.txt": _requirements, "package.json": _package_json}


def components(files: dict[str, str]) -> list[dict[str, str]]:
    """(path → text) of one target → sorted unique components with the file each came from."""
    dirs_with_lock = {p.rsplit("/", 1)[0] for p in files if p.endswith("/package-lock.json")}
    seen: dict[str, dict[str, str]] = {}
    for path, text in sorted(files.items()):
        base = path.rsplit("/", 1)[-1]
        reader = READERS.get(base)
        if not reader or "/node_modules/" in path or (base == "package.json" and path.rsplit("/", 1)[0] in dirs_with_lock):
            continue
        try:
            rows = reader(text)
        except (ValueError, KeyError, TypeError, tomllib.TOMLDecodeError):
            continue   # a malformed manifest in a scanned repo is the repo's problem, not a reason to stop the station
        for kind, name, version in rows:
            purl = _purl(kind, name, version)
            seen.setdefault(purl, {"purl": purl, "name": name, "version": version, "file": path})
    return [seen[k] for k in sorted(seen)]


def sbom(comps: list[dict[str, str]], name: str) -> dict[str, Any]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": name}},
            "components": [{"type": "library", "bom-ref": f"c{i}", "name": c["name"], "version": c["version"], "purl": c["purl"]}
                           for i, c in enumerate(comps)]}


def findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    """ScanSbom answer (CycloneDX with `vulnerabilities`) → one row per (vulnerability, package)."""
    bom = result.get("sbom") or result
    refs = {c.get("bom-ref"): c.get("purl") for c in bom.get("components") or []}
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for v in bom.get("vulnerabilities") or []:
        sev = ((v.get("ratings") or [{}])[0].get("severity") or "unknown").lower()
        props = {p.get("name"): p.get("value") for p in v.get("properties") or []}
        for a in v.get("affects") or []:
            purl = refs.get(a.get("ref"))
            if purl:   # the fixed version is per affected component: amazon:inspector:sbom_scanner:fixed_version:<ref>
                fixed = props.get(f"amazon:inspector:sbom_scanner:fixed_version:{a.get('ref')}")
                out[(v["id"], purl)] = {"id": v["id"], "severity": sev if sev in SEVERITY_ORDER else "unknown", "purl": purl,
                                        "fixed": fixed or None, "cwes": [f"CWE-{c}" for c in v.get("cwes") or []]}
    return sorted(out.values(), key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["id"], f["purl"]))


def for_event(cves: list[str], target_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    want = set(cves)
    return [f for f in target_findings if f["id"] in want]
