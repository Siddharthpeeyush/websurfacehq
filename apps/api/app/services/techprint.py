"""Tech fingerprinting from httpx probe results (Week 2 recon,
``tech_fingerprint`` stage).

Pure functions over supplied probe dicts — this module performs NO network
I/O. The caller (workstream B's ``http_probe`` stage) supplies one httpx
result dict per host; this module only interprets what is in it.

A technology is reported only when the input evidences it (httpx ``tech``
list, a Server / X-Powered-By / other header, a Set-Cookie name, or a
``body_snippet`` hint). Unknown input yields an empty technology list —
never a guess.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

# Canonical display name per lowercased technology name. Used to normalise
# httpx ``tech`` entries (e.g. "nginx" -> "Nginx") so dedupe is stable.
_CANONICAL_TECH: dict[str, str] = {
    "nginx": "Nginx",
    "apache": "Apache",
    "apache http server": "Apache",
    "openresty": "OpenResty",
    "cloudflare": "Cloudflare",
    "express": "Express",
    "express.js": "Express",
    "next.js": "Next.js",
    "nextjs": "Next.js",
    "wordpress": "WordPress",
    "php": "PHP",
    "django": "Django",
    "ruby on rails": "Ruby on Rails",
    "rails": "Ruby on Rails",
    "vercel": "Vercel",
    "netlify": "Netlify",
    "amazon cloudfront": "Amazon CloudFront",
    "cloudfront": "Amazon CloudFront",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "varnish": "Varnish",
    "haproxy": "HAProxy",
    "caddy": "Caddy",
    "litespeed": "LiteSpeed",
    "microsoft-iis": "IIS",
    "iis": "IIS",
    "tomcat": "Apache Tomcat",
    "jetty": "Jetty",
    "gunicorn": "Gunicorn",
    "uvicorn": "Uvicorn",
    "werkzeug": "Werkzeug",
    "flask": "Flask",
    "fastapi": "FastAPI",
    "node.js": "Node.js",
    "node": "Node.js",
    "asp.net": "ASP.NET",
    "laravel": "Laravel",
    "shopify": "Shopify",
    "joomla": "Joomla",
    "drupal": "Drupal",
    "ghost": "Ghost",
    "gatsby": "Gatsby",
    "nuxt.js": "Nuxt.js",
    "nuxt": "Nuxt.js",
    "hugo": "Hugo",
    "jekyll": "Jekyll",
    "react": "React",
    "vue.js": "Vue.js",
    "vue": "Vue.js",
    "angular": "Angular",
    "jquery": "jQuery",
    "tailwind css": "Tailwind CSS",
    "tailwind": "Tailwind CSS",
    "bootstrap": "Bootstrap",
    "svelte": "Svelte",
    "java": "Java",
    "nextauth": "NextAuth",
    "next-auth": "NextAuth",
    "github pages": "GitHub Pages",
}

# (substring, display name) markers for header values (Server,
# X-Powered-By, X-Generator, webserver field). Substring matching is safe
# here: header values are short, controlled tokens such as "nginx/1.25.4".
_HEADER_MARKERS: tuple[tuple[str, str], ...] = (
    ("nginx", "Nginx"),
    ("apache", "Apache"),
    ("openresty", "OpenResty"),
    ("cloudflare", "Cloudflare"),
    ("express", "Express"),
    ("next.js", "Next.js"),
    ("php", "PHP"),
    ("asp.net", "ASP.NET"),
    ("django", "Django"),
    ("ruby on rails", "Ruby on Rails"),
    ("rails", "Ruby on Rails"),
    ("vercel", "Vercel"),
    ("netlify", "Netlify"),
    ("cloudfront", "Amazon CloudFront"),
    ("akamai", "Akamai"),
    ("fastly", "Fastly"),
    ("varnish", "Varnish"),
    ("haproxy", "HAProxy"),
    ("caddy", "Caddy"),
    ("litespeed", "LiteSpeed"),
    ("microsoft-iis", "IIS"),
    ("tomcat", "Apache Tomcat"),
    ("jetty", "Jetty"),
    ("gunicorn", "Gunicorn"),
    ("uvicorn", "Uvicorn"),
    ("werkzeug", "Werkzeug"),
    ("flask", "Flask"),
    ("fastapi", "FastAPI"),
    ("node.js", "Node.js"),
    ("laravel", "Laravel"),
    ("shopify", "Shopify"),
    ("wordpress", "WordPress"),
    ("joomla", "Joomla"),
    ("drupal", "Drupal"),
    ("github.com", "GitHub Pages"),
)

# (substring, display name) markers for a body snippet. Deliberately
# stricter than the header list: bare words such as "vue" or "react"
# appear in prose, so only distinctive tokens are matched here.
_BODY_MARKERS: tuple[tuple[str, str], ...] = (
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("wp-json", "WordPress"),
    ("wordpress", "WordPress"),
    ("_next/static", "Next.js"),
    ("__next_data__", "Next.js"),
    ("next.js", "Next.js"),
    ("vue.js", "Vue.js"),
    ("react-dom", "React"),
    ("react.production", "React"),
    ("angular.js", "Angular"),
    ("jquery", "jQuery"),
    ("bootstrap", "Bootstrap"),
    ("tailwind", "Tailwind CSS"),
    ("svelte", "Svelte"),
    ("drupal", "Drupal"),
    ("joomla", "Joomla"),
    ("ghost", "Ghost"),
    ("nuxt", "Nuxt.js"),
    ("hugo", "Hugo"),
    ("jekyll", "Jekyll"),
    ("gatsby", "Gatsby"),
    ("laravel", "Laravel"),
    ("django", "Django"),
    ("shopify", "Shopify"),
    ("ruby on rails", "Ruby on Rails"),
)

_GENERATOR_META_RE = re.compile(
    r"<meta[^>]*name=[\"']generator[\"'][^>]*content=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_TLS_VERSION_RE = re.compile(r"(?:TLS|SSL)[ _/v-]?(\d+)\.(\d+)", re.IGNORECASE)


def _canonical_name(name: str) -> str:
    """Canonical display name for a technology, or the name as given."""
    return _CANONICAL_TECH.get(name.strip().lower(), name.strip())


def _techs_from_text(text: str, markers: tuple[tuple[str, str], ...]) -> set[str]:
    """Technologies evidenced by substring markers in ``text``."""
    lowered = text.lower()
    return {display for marker, display in markers if marker in lowered}


def _normalized_headers(headers: object) -> dict[str, str]:
    """Case-insensitive header lookup: lowercased name -> first value.

    Non-dict / non-string input yields an empty dict (never a crash on a
    malformed probe result). List values are joined with "; ".
    """
    if not isinstance(headers, dict):
        return {}
    out: dict[str, str] = {}
    for raw_name, raw_value in headers.items():
        if not isinstance(raw_name, str):
            continue
        if isinstance(raw_value, list):
            value = "; ".join(str(item) for item in raw_value)
        elif isinstance(raw_value, str):
            value = raw_value
        else:
            continue
        out.setdefault(raw_name.lower(), value)
    return out


def _cookie_techs(headers: dict[str, str]) -> set[str]:
    """Technologies evidenced by Set-Cookie names (framework sessions)."""
    techs: set[str] = set()
    raw = headers.get("set-cookie", "")
    for part in raw.split(";"):
        name = part.strip().split("=", 1)[0].strip().lower()
        if not name:
            continue
        if name.startswith("wordpress_") or name.startswith("wp-"):
            techs.add("WordPress")
        elif name == "phpsessid":
            techs.add("PHP")
        elif name == "jsessionid":
            techs.add("Java")
        elif name == "connect.sid":
            techs.add("Express")
        elif name in ("laravel_session", "xsrf-token"):
            techs.add("Laravel")
        elif name in ("csrftoken", "sessionid"):
            techs.add("Django")
        elif name.startswith("next-auth"):
            techs.add("NextAuth")
        elif "shopify" in name:
            techs.add("Shopify")
    return techs


def _header_name_techs(headers: dict[str, str]) -> set[str]:
    """Technologies evidenced by the mere presence of a header name."""
    techs: set[str] = set()
    for name in headers:
        if name.startswith("x-vercel"):
            techs.add("Vercel")
        elif name.startswith("cf-"):
            techs.add("Cloudflare")
        elif name.startswith("x-amz-cf"):
            techs.add("Amazon CloudFront")
        elif name.startswith("x-netlify"):
            techs.add("Netlify")
        elif name.startswith("x-shopify"):
            techs.add("Shopify")
        elif name == "x-drupal-cache":
            techs.add("Drupal")
        elif name in ("x-aspnet-version", "x-aspnetmvc-version"):
            techs.add("ASP.NET")
    return techs


def _body_techs(body: str) -> set[str]:
    """Technologies evidenced by a body snippet (meta generator + hints)."""
    techs = _techs_from_text(body, _BODY_MARKERS)
    match = _GENERATOR_META_RE.search(body)
    if match:
        # "WordPress 6.4" -> "WordPress"; an unknown generator keeps its
        # own first token — it is evidenced by the page itself, not a guess.
        token = match.group(1).strip().split(" ", 1)[0]
        if token and len(token) <= 40 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", token):
            techs.add(_canonical_name(token))
    return techs


def _normalize_tls_version(raw: object) -> str | None:
    """Normalise a TLS version string to ``TLS x.y`` / ``SSL x.y``.

    Accepts "TLSv1.3", "tls13", "1.3", "TLS 1.3" and friends; an
    unrecognised non-empty string is returned stripped, as given.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    match = _TLS_VERSION_RE.search(text)
    if match:
        major, minor = match.group(1), match.group(2)
        family = "SSL" if text.lower().startswith("ssl") else "TLS"
        return f"{family} {major}.{minor}"
    compact = re.fullmatch(r"(?i)tls(\d)(\d)", text)
    if compact:
        return f"TLS {compact.group(1)}.{compact.group(2)}"
    bare = re.fullmatch(r"(\d)\.(\d)", text)
    if bare:
        return f"TLS {bare.group(1)}.{bare.group(2)}"
    return text


def _parse_not_after(raw: object) -> datetime | None:
    """Parse a TLS not_after value (ISO string or datetime), else None."""
    if isinstance(raw, datetime):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    return None


def _str_field(value: object) -> str | None:
    """A string field, stripped, or None when absent / blank / not a str."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def tls_summary(tls_info: dict[str, Any] | None) -> dict[str, Any]:
    """Summarise TLS info from one httpx probe result.

    Keys: ``version`` (normalised, e.g. "TLS 1.3"), ``issuer``,
    ``not_after`` (raw string as supplied), ``expired`` (bool), ``self_signed``
    (bool) and ``grade_hint`` (``ok`` | ``weak`` | ``expired`` | ``unknown``,
    derived from version/expiry only — never a full grade claim).
    ``None`` / missing input yields all-None fields + ``unknown`` hint.
    The agent's httpx key spellings are accepted too: ``tls_version``
    for ``version``, ``issuer_cn`` for ``issuer`` and ``subject_cn``
    for ``subject`` (B3 contract fix — the Go side keeps its keys).
    """
    empty: dict[str, Any] = {
        "version": None,
        "issuer": None,
        "not_after": None,
        "expired": None,
        "self_signed": None,
        "grade_hint": "unknown",
    }
    if not isinstance(tls_info, dict):
        return empty
    version = _normalize_tls_version(tls_info.get("version") or tls_info.get("tls_version"))
    issuer_raw = tls_info.get("issuer")
    if issuer_raw is None:
        # The agent emits the httpx field name "issuer_cn" (B3 contract
        # fix — the Go side keeps its keys; Python accepts both).
        issuer_raw = tls_info.get("issuer_cn")
    issuer: str | None = None
    if isinstance(issuer_raw, str):
        issuer = _str_field(issuer_raw)
    elif isinstance(issuer_raw, dict):
        for key in ("CN", "commonName", "O", "organization"):
            issuer = _str_field(issuer_raw.get(key))
            if issuer is not None:
                break
    not_after_raw = (
        tls_info.get("not_after")
        or tls_info.get("notAfter")
        or tls_info.get("expiry")
        or tls_info.get("expires")
    )
    not_after = _str_field(not_after_raw)
    if not_after is None and isinstance(not_after_raw, datetime):
        not_after = not_after_raw.isoformat()
    expired_raw = tls_info.get("expired")
    expired: bool | None = expired_raw if isinstance(expired_raw, bool) else None
    if expired is None:
        parsed = _parse_not_after(not_after_raw)
        if parsed is not None:
            expired = parsed < datetime.now(timezone.utc)
    self_signed_raw = tls_info.get("self_signed")
    self_signed: bool | None = self_signed_raw if isinstance(self_signed_raw, bool) else None
    if self_signed is None:
        # The agent emits the httpx field name "subject_cn" (B3).
        subject = _str_field(tls_info.get("subject")) or _str_field(tls_info.get("subject_cn"))
        if issuer is not None and subject is not None:
            self_signed = issuer == subject
    if expired is True:
        grade_hint = "expired"
    elif version in ("TLS 1.0", "TLS 1.1", "SSL 2.0", "SSL 3.0"):
        grade_hint = "weak"
    elif version in ("TLS 1.2", "TLS 1.3"):
        grade_hint = "ok"
    else:
        grade_hint = "unknown"
    return {
        "version": version,
        "issuer": issuer,
        "not_after": not_after,
        "expired": expired,
        "self_signed": self_signed,
        "grade_hint": grade_hint,
    }


def fingerprint(host_result: dict[str, Any]) -> dict[str, Any]:
    """Fingerprint one httpx probe result dict.

    Input keys (all optional): ``url``, ``host``, ``ip``, ``status_code``
    (or ``status``), ``title``, ``tech`` (list) or ``technologies``
    (list — the agent's key, preferred when present), ``headers``
    (dict), ``tls`` (dict — accepts the agent's ``issuer_cn`` /
    ``subject_cn`` / ``tls_version`` keys as well as ``issuer`` /
    ``subject`` / ``version``), ``webserver``, ``content_type``,
    ``body_snippet``.

    Output keys: ``technologies`` (sorted deduped list),
    ``webserver`` (str | None), ``tls`` (:func:`tls_summary` dict),
    ``headers`` (``server`` / ``x_powered_by`` / ``content_type``, each a
    value or None), ``title`` (str | None), ``status_code`` (int | None).
    """
    headers = _normalized_headers(host_result.get("headers"))
    techs: set[str] = set()
    # The agent emits "technologies"; older/httpx-shaped input uses
    # "tech". Prefer "technologies" when it is a non-empty list (B3).
    raw_tech = host_result.get("technologies") or host_result.get("tech")
    if isinstance(raw_tech, list):
        for entry in raw_tech:
            if isinstance(entry, str) and entry.strip():
                techs.add(_canonical_name(entry))
    for header_name in ("server", "x-powered-by", "x-generator"):
        value = headers.get(header_name)
        if value:
            techs |= _techs_from_text(value, _HEADER_MARKERS)
    techs |= _header_name_techs(headers)
    techs |= _cookie_techs(headers)
    body = host_result.get("body_snippet")
    if isinstance(body, str) and body.strip():
        techs |= _body_techs(body)
    webserver_raw = host_result.get("webserver")
    webserver: str | None = None
    if isinstance(webserver_raw, str) and webserver_raw.strip():
        webserver = webserver_raw.strip()
        techs |= _techs_from_text(webserver, _HEADER_MARKERS)
    elif headers.get("server"):
        webserver = headers["server"]
    content_type = _str_field(host_result.get("content_type")) or headers.get("content-type")
    status_raw = host_result.get("status_code")
    if status_raw is None:
        # The agent also emits "status" (same value); accept it so a
        # probe record that only carries "status" still counts as live.
        status_raw = host_result.get("status")
    status_code: int | None = None
    if isinstance(status_raw, int) and not isinstance(status_raw, bool):
        status_code = status_raw
    elif isinstance(status_raw, str) and status_raw.strip().isdigit():
        status_code = int(status_raw.strip())
    tls_raw = host_result.get("tls")
    return {
        "technologies": sorted(techs),
        "webserver": webserver,
        "tls": tls_summary(tls_raw if isinstance(tls_raw, dict) else None),
        "headers": {
            "server": headers.get("server"),
            "x_powered_by": headers.get("x-powered-by"),
            "content_type": content_type,
        },
        "title": _str_field(host_result.get("title")),
        "status_code": status_code,
    }


def summarize_http_probe(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate fingerprints over a list of httpx probe result dicts.

    ``counts``: ``hosts`` (probes supplied), ``live`` (probes that returned
    any status code) and ``by_status_class`` (``2xx`` / ``3xx`` / ``4xx`` /
    ``5xx`` / ``no_response``). Also the union of ``technologies``, the
    ``tls_versions`` seen and the ``webservers`` seen (each sorted).
    """
    by_status_class: dict[str, int] = {
        "2xx": 0,
        "3xx": 0,
        "4xx": 0,
        "5xx": 0,
        "no_response": 0,
    }
    live = 0
    techs: set[str] = set()
    tls_versions: set[str] = set()
    webservers: set[str] = set()
    for result in results:
        probe = fingerprint(result)
        status = probe["status_code"]
        if status is None:
            by_status_class["no_response"] += 1
        else:
            live += 1
            by_status_class[f"{status // 100}xx"] += 1
        techs.update(str(item) for item in probe["technologies"])
        version = probe["tls"]["version"]
        if isinstance(version, str) and version:
            tls_versions.add(version)
        server = probe["webserver"]
        if isinstance(server, str) and server:
            webservers.add(server)
    return {
        "counts": {
            "hosts": len(results),
            "live": live,
            "by_status_class": by_status_class,
        },
        "technologies": sorted(techs),
        "tls_versions": sorted(tls_versions),
        "webservers": sorted(webservers),
    }
