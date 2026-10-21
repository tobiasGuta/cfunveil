"""Small bounded-retry HTTP helpers for passive intelligence sources."""
import asyncio
import time

import aiohttp


async def _retry_request(session, method, url, *, headers=None, params=None,
                         json_body=None, attempts=3, timeout=10):
    for index in range(max(1, attempts)):
        try:
            kwargs = {
                "headers": headers,
                "timeout": aiohttp.ClientTimeout(total=timeout),
            }
            if params is not None:
                kwargs["params"] = params
            if json_body is not None:
                kwargs["json"] = json_body
            async with getattr(session, method)(url, **kwargs) as response:
                # Consumers parse JSON/text after this helper exits; pre-buffer the
                # body so it is still available when aiohttp closes the response.
                await response.read()
                if response.status not in (429, 503) or index == attempts - 1:
                    return response
        except asyncio.CancelledError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError):
            if index == attempts - 1:
                return None
        await asyncio.sleep(min(2 ** index, 8))
    return None


async def http_get_with_retry(session, url: str, headers=None, params=None,
                              attempts=3, timeout=10):
    return await _retry_request(
        session, "get", url, headers=headers, params=params,
        attempts=attempts, timeout=timeout,
    )


async def http_post_with_retry(session, url: str, json_body=None, headers=None,
                               attempts=3, timeout=10):
    return await _retry_request(
        session, "post", url, json_body=json_body, headers=headers,
        attempts=attempts, timeout=timeout,
    )


def sync_retry(func, *args, attempts=3, backoff_base=1.0,
               exceptions=(Exception,), **kwargs):
    backoff = backoff_base
    for attempt in range(attempts):
        try:
            return func(*args, **kwargs)
        except exceptions:
            if attempt == attempts - 1:
                raise
            time.sleep(backoff)
            backoff *= 2
