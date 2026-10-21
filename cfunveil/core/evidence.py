"""Host-specific discovery evidence; timestamps never substitute for live validation.

A fresh passive observation can be a useful lead, but neither recent passive DNS
nor currently observed DNS independently proves application ownership or access.
"""
from datetime import datetime, timezone, timedelta
import re

_CURRENT_DNS_TYPES = frozenset({
    "A", "AAAA", "CNAME-A", "CNAME-AAAA", "cert-hostname-DNS-A",
})
_RECENT_WINDOW = timedelta(days=90)


def parse_observation_time(value):
    """Parse a trustworthy full date or Unix epoch; reject partial/ambiguous dates."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if not (946684800 <= number <= 4102444800):  # 2000-01-01..2100-01-01
            return None
        return datetime.fromtimestamp(number, tz=timezone.utc)
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    if re.fullmatch(r"\d{10}(?:\.\d+)?", value):
        return parse_observation_time(float(value))
    if not re.match(r"^\d{4}-\d{2}-\d{2}(?:$|T| )", value):
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def classify_target_evidence(target, records, *, as_of=None):
    """Return current DNS vs dated/undated exact-target historical evidence.

    Current means queried during *this run*, NOT validated as the application's
    origin. A historical record's last_seen describes the data provider's
    observation, not a current reachability or ownership assertion.
    """
    as_of = as_of or datetime.now(timezone.utc)
    if as_of.tzinfo is None:
        raise ValueError("as_of must be timezone-aware")
    as_of = as_of.astimezone(timezone.utc)
    target = target.rstrip(".").lower()
    any_exact = False
    times = []
    for record in records:
        if not isinstance(record, dict):
            continue
        if str(record.get("domain") or "").lower().rstrip(".") != target:
            continue
        any_exact = True
        if record.get("record_type") in _CURRENT_DNS_TYPES:
            return {
                "evidence_status": "current_dns_observed",
                "evidence_last_seen": None,
            }
        timestamp = parse_observation_time(record.get("last_seen"))
        if timestamp is not None and timestamp <= as_of:
            times.append(timestamp)
    if not any_exact:
        return {"evidence_status": "no_exact_target_evidence", "evidence_last_seen": None}
    if not times:
        return {"evidence_status": "historical_undated", "evidence_last_seen": None}
    latest = max(times)
    return {
        "evidence_status": (
            "historical_recent" if as_of - latest <= _RECENT_WINDOW
            else "historical_stale"
        ),
        "evidence_last_seen": latest.isoformat(),
    }
