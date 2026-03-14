"""core/utils.py

Small helpers: HTTP get with retry/backoff for aiohttp and sync search retry for blocking APIs.
"""
import asyncio
import time
from typing import Optional


async def http_get_with_retry(session, url: str, headers: dict = None, params: dict = None, attempts: int = 3, timeout: int = 10):
    backoff = 1
    for attempt in range(attempts):
        try:
            async with session.get(url, headers=headers, params=params, timeout=None) as resp:
                # Respect HTTP 429/503 as retriable
                if resp.status in (429, 503):
                    if attempt < attempts - 1:
                        await asyncio.sleep(backoff)
                        backoff *= 2
                        continue
                    else:
                        return resp
                return resp
        except asyncio.CancelledError:
            raise


async def http_post_with_retry(session, url: str, json_body: dict = None, headers: dict = None, attempts: int = 3, timeout: int = 10):
    backoff = 1
    for attempt in range(attempts):
        try:
            async with session.post(url, headers=headers, json=json_body, timeout=None) as resp:
                if resp.status in (429, 503):
                    if attempt < attempts - 1:
                        await asyncio.sleep(backoff)
                        backoff *= 2
                        continue
                    else:
                        return resp
                return resp
        except asyncio.CancelledError:
            raise
        except Exception:
            if attempt < attempts - 1:
                await asyncio.sleep(backoff)
                backoff *= 2
                continue
            raise
        except Exception:
            if attempt < attempts - 1:
                await asyncio.sleep(backoff)
                backoff *= 2
                continue
            raise


def sync_retry(func, *args, attempts: int = 3, backoff_base: float = 1.0, exceptions=(Exception,), **kwargs):
    """Run a synchronous function with retries/backoff. Returns function result or raises last exception."""
    backoff = backoff_base
    last_exc = None
    for attempt in range(attempts):
        try:
            return func(*args, **kwargs)
        except exceptions as e:
            last_exc = e
            if attempt < attempts - 1:
                time.sleep(backoff)
                backoff *= 2
                continue
            raise
