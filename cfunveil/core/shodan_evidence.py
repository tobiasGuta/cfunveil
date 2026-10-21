"""Pure Shodan evidence normalization; never turns search matches into origin proof.

The *requested* hostname and public-suffix-aware registrable root come from the
scan engine. A substring, certificate, favicon, or Shodan search hit alone cannot
establish the requested hostname's current DNS address or application origin.
"""

from collections.abc import Mapping


FINGERPRINT_STRATEGIES = frozenset({"favicon_hash", "jarm", "http_headers"})


def _hostname(value):
    if not isinstance(value, str):
        return ""
    name = value.strip().lower().rstrip(".")
    # Shodan data is untrusted; avoid treating URLs or free text as DNS names.
    if not name or "/" in name or " " in name or "://" in name:
        return ""
    return name


def _names(value):
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = []
    return sorted({name for v in values if (name := _hostname(v))})


def _certificate_names(result):
    ssl = result.get("ssl")
    if not isinstance(ssl, Mapping):
        return []
    cert = ssl.get("cert")
    if not isinstance(cert, Mapping):
        return []
    subject = cert.get("subject")
    subject = subject if isinstance(subject, Mapping) else {}
    names = _names(subject.get("CN") or subject.get("cn"))
    names.extend(_names(cert.get("alt_names")))
    return sorted(set(names))


def describe_shodan_match(result: Mapping, *, target: str, root_domain: str,
                          strategy: str, query: str) -> dict:
    """Return a compact, self-contained observation suitable for JSON export.

    Hostname relationships derive solely from Shodan's explicit observed
    hostnames, not broad 'domains' suffixes, search keywords, or certificate CN.
    Other matching mechanisms remain context and cannot become current DNS.
    """
    target = _hostname(target)
    root_domain = _hostname(root_domain)
    hostnames = _names(result.get("hostnames"))
    exact = [h for h in hostnames if h == target]
    related = [
        h for h in hostnames
        if h != target and (h == root_domain or h.endswith("." + root_domain))
    ]

    relation = (
        "exact_target_hostname" if exact else
        "related_hostname" if related else
        "fingerprint_only" if strategy in FINGERPRINT_STRATEGIES else
        "query_only"
    )

    timestamp = result.get("timestamp") or result.get("last_update")
    if not isinstance(timestamp, str) or not timestamp.strip():
        timestamp = None

    port = result.get("port")
    port = port if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535 else None
    ssl_data = result.get("ssl")
    ssl_data = ssl_data if isinstance(ssl_data, Mapping) else {}

    return {
        "strategy": strategy,
        "query": query,
        "relation": relation,
        "hostnames": hostnames,
        "exact_hostnames": exact,
        "related_hostnames": related,
        "certificate_names": _certificate_names(result),
        "observed_at": timestamp,
        "port": port,
        "product": result.get("product") if isinstance(result.get("product"), str) else None,
        "version": result.get("version") if isinstance(result.get("version"), str) else None,
        "jarm": ssl_data.get("jarm") if isinstance(ssl_data.get("jarm"), str) else None,
    }
