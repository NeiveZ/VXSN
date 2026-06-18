#!/usr/bin/env python3
# utils/http_client.py — Shared HTTP client for VXSN modules

import urllib.request
import urllib.parse
import urllib.error
import ssl
import random
import time


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
]


class HTTPClient:
    """Shared HTTP client used by all VXSN modules."""

    def __init__(self, timeout: int = 10, delay: float = 0.0,
                 follow_redirects: bool = True, verify_ssl: bool = False):
        self.timeout          = timeout
        self.delay            = delay
        self.follow_redirects = follow_redirects
        self._ctx = ssl.create_default_context()
        if not verify_ssl:
            self._ctx.check_hostname = False
            self._ctx.verify_mode    = ssl.CERT_NONE

    def _get_ua(self) -> str:
        return random.choice(USER_AGENTS)

    def get(self, url: str, params: dict = None) -> tuple[int, str, dict]:
        """
        Send GET request.
        Returns: (status_code, body, headers)
        """
        if params:
            url = url + "?" + urllib.parse.urlencode(params)

        if self.delay > 0:
            time.sleep(self.delay)

        req = urllib.request.Request(url, headers={"User-Agent": self._get_ua()})
        handler = urllib.request.HTTPSHandler(context=self._ctx)

        if not self.follow_redirects:
            opener = urllib.request.build_opener(handler, NoRedirectHandler())
        else:
            opener = urllib.request.build_opener(handler)

        try:
            with opener.open(req, timeout=self.timeout) as resp:
                body    = resp.read(1024 * 512).decode("utf-8", errors="replace")
                headers = dict(resp.headers)
                return resp.status, body, headers
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read(1024 * 32).decode("utf-8", errors="replace")
            except Exception:
                pass
            return e.code, body, dict(e.headers)
        except Exception:
            return 0, "", {}

    def post(self, url: str, data: dict = None, raw: str = None) -> tuple[int, str, dict]:
        """
        Send POST request.
        Returns: (status_code, body, headers)
        """
        if self.delay > 0:
            time.sleep(self.delay)

        if raw is not None:
            post_data = raw.encode()
            content_type = "application/x-www-form-urlencoded"
        elif data:
            post_data    = urllib.parse.urlencode(data).encode()
            content_type = "application/x-www-form-urlencoded"
        else:
            post_data    = b""
            content_type = "application/x-www-form-urlencoded"

        req = urllib.request.Request(
            url,
            data    = post_data,
            headers = {
                "User-Agent":   self._get_ua(),
                "Content-Type": content_type,
            }
        )
        handler = urllib.request.HTTPSHandler(context=self._ctx)
        opener  = urllib.request.build_opener(handler)

        try:
            with opener.open(req, timeout=self.timeout) as resp:
                body    = resp.read(1024 * 512).decode("utf-8", errors="replace")
                headers = dict(resp.headers)
                return resp.status, body, headers
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read(1024 * 32).decode("utf-8", errors="replace")
            except Exception:
                pass
            return e.code, body, dict(e.headers)
        except Exception:
            return 0, "", {}


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
