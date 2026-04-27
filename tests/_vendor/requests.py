#!/usr/bin/env python3
"""
#exonware/xwauth-identity/tests/_vendor/requests.py
Minimal requests-compatible test shim for offline unit tests.
"""

from __future__ import annotations

from typing import Any


class _CookieJar:
    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    def set(self, key: str, value: str, domain: str | None = None) -> None:
        self._values[key] = value

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._values.get(key, default)


class Response:
    def __init__(self, status_code: int = 200, text: str = "", json_data: Any | None = None) -> None:
        self.status_code = status_code
        self.text = text
        self._json_data = json_data

    def json(self) -> Any:
        return self._json_data


class Session:
    def __init__(self) -> None:
        self.cookies = _CookieJar()
        self.headers: dict[str, str] = {}

    def close(self) -> None:
        return None

    def request(self, method: str, url: str, **kwargs: Any) -> Response:
        raise NotImplementedError("requests.Session shim does not perform real HTTP")

    def get(self, url: str, **kwargs: Any) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> Response:
        return self.request("DELETE", url, **kwargs)


def request(method: str, url: str, **kwargs: Any) -> Response:
    return Session().request(method, url, **kwargs)


def get(url: str, **kwargs: Any) -> Response:
    return request("GET", url, **kwargs)


def post(url: str, **kwargs: Any) -> Response:
    return request("POST", url, **kwargs)
