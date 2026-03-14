"""
core/email_header.py - Parse raw email headers and optionally fetch headers via IMAP

Functions:
- parse_email_headers(raw) -> list of IPv4/IPv6 strings
- fetch_headers_via_imap(host, user, password, mailbox, ssl, limit) -> raw headers string

Note: IMAP fetching runs in a thread to avoid blocking asyncio code.
"""
import re
import ipaddress
import imaplib
from typing import List

RECEIVED_RE = re.compile(r"^Received:\s*(.*)$", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_email_headers(raw: str) -> List[str]:
    """Extract IP addresses from Received headers in raw email headers text."""
    ips = set()
    for line in raw.splitlines():
        m = RECEIVED_RE.match(line.strip())
        if m:
            text = m.group(1)
            for candidate in IP_RE.findall(text):
                try:
                    ipaddress.ip_address(candidate)
                    ips.add(candidate)
                except Exception:
                    continue
    return list(ips)


def fetch_headers_via_imap(host: str, user: str, password: str, mailbox: str = "INBOX", use_ssl: bool = True, limit: int = 1) -> str:
    """Connect to IMAP server and fetch the most recent `limit` messages' headers as a single raw string.

    This is synchronous by design; callers should run it in an executor if used inside asyncio.
    """
    flags = imaplib.IMAP4_SSL if use_ssl else imaplib.IMAP4
    conn = flags(host)
    conn.login(user, password)
    conn.select(mailbox)
    # search ALL and fetch the latest `limit` messages
    typ, data = conn.search(None, 'ALL')
    if typ != 'OK' or not data or not data[0]:
        conn.logout()
        return ""

    ids = data[0].split()
    selected = ids[-limit:]
    headers = []
    for msgid in selected:
        typ, resp = conn.fetch(msgid, '(BODY.PEEK[HEADER])')
        if typ != 'OK':
            continue
        parts = []
        for item in resp:
            if isinstance(item, tuple):
                parts.append(item[1].decode('utf-8', errors='ignore'))
        headers.append('\n'.join(parts))

    conn.logout()
    return '\n\n'.join(headers)
