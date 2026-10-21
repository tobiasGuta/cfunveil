"""Offline, public-suffix-aware hostname boundary for reconnaissance.

Using a bundled Public Suffix List snapshot ensures that merely parsing a
hostname never makes outbound network requests. Include private suffixes:
different tenants of github.io/blogspot.com are different authorization scopes.
"""
import tldextract

_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    include_psl_private_domains=True,
)


def registrable_domain(hostname: str) -> str:
    if not isinstance(hostname, str):
        raise ValueError("target must be a domain name")
    hostname = hostname.strip().lower().rstrip(".")
    if not hostname or "://" in hostname or "/" in hostname:
        raise ValueError("target must be a domain name, not a URL")
    result = _EXTRACT(hostname)
    if not result.domain or not result.suffix:
        raise ValueError("target has no registrable domain under the bundled suffix list")
    root = result.top_domain_under_public_suffix
    if not root or not (
        hostname == root or hostname.endswith("." + root)
    ):
        raise ValueError("target is not inside a valid registrable domain")
    return root
