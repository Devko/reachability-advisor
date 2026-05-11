"""Small purl parser used for matching and ecosystem detection."""

from __future__ import annotations

from urllib.parse import unquote

from .models import PackageUrl


def parse_purl(value: str | None) -> PackageUrl | None:
    if not value or not value.startswith("pkg:"):
        return None
    raw = value
    body = value[4:]
    body = body.split("?", 1)[0].split("#", 1)[0]
    if "/" not in body:
        return PackageUrl(raw=raw, ptype=unquote(body))
    ptype, rest = body.split("/", 1)
    version = None
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version)
    parts = [unquote(p) for p in rest.split("/") if p]
    if not parts:
        return PackageUrl(raw=raw, ptype=unquote(ptype))
    name = parts[-1]
    namespace = "/".join(parts[:-1]) or None
    return PackageUrl(raw=raw, ptype=unquote(ptype), namespace=namespace, name=name, version=version)


def package_match(component_name: str, component_purl: str | None, vuln_name: str, vuln_purl: str | None) -> bool:
    """Return true if a vulnerability record plausibly targets the component."""

    comp = parse_purl(component_purl)
    vuln = parse_purl(vuln_purl)
    if component_purl and vuln_purl and component_purl == vuln_purl:
        return True
    if comp and vuln and comp.ptype == vuln.ptype and comp.name == vuln.name:
        return not (vuln.namespace and comp.namespace != vuln.namespace)
    normalized_component = component_name.lower().replace("_", "-")
    normalized_vuln = vuln_name.lower().replace("_", "-")
    return normalized_component == normalized_vuln


def ecosystem_from_component(component_purl: str | None, component_name: str) -> str:
    parsed = parse_purl(component_purl)
    if parsed and parsed.ecosystem:
        return parsed.ecosystem
    if component_name.startswith("@"):
        return "npm"
    return "unknown"
