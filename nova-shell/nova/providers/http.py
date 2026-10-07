from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Iterator

from nova.errors import ProviderError
from nova.ick import KernelRefusal
from runtime.chat import direct_calls_allowed, warn_direct_calls

# Some hosts (Groq's CDN, for one) reject Python's default urllib user agent with a 403.
USER_AGENT = "infinity-core-nova/0.1"


def kernel_gate_is_on() -> bool:
    """True when a policy file or a signer service is configured."""
    return bool(
        (os.environ.get("NOVA_ICK_POLICY") or "").strip()
        or (os.environ.get("NOVA_ICK_SERVICE") or "").strip()
    )


def refuse_unconfigured_model_http() -> None:
    """Stop before Nova's provider client opens a connection.

    A configured kernel gate belongs to the witness. With the gate off, nothing is
    sent unless ``WICKET_ALLOW_DIRECT_CALLS`` is exactly ``1``. This does not warn;
    the send itself does.
    """
    if kernel_gate_is_on():
        raise KernelRefusal(
            code="WITNESS_REQUIRED",
            message="the gate is on; a known-shape HTTP call is sent by the witness, not by this client",
        )
    if not direct_calls_allowed():
        raise KernelRefusal(
            code="WITNESS_REQUIRED",
            message="nothing is sent unless a policy and a witness are configured",
        )


def begin_direct_model_http() -> None:
    """The local-dev send. Refuses, or warns on stderr and returns."""
    refuse_unconfigured_model_http()
    warn_direct_calls()


def post_json(
    url: str,
    payload: dict[str, Any],
    *,
    timeout: float,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    begin_direct_model_http()
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT, **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise ProviderError(code="PROVIDER_HTTP_ERROR", message=f"{exc.code}: {exc.read().decode('utf-8')[:256]}") from exc
    except urllib.error.URLError as exc:
        raise ProviderError(code="PROVIDER_REQUEST_FAILED", message=str(exc)) from exc
    if status != 200:
        raise ProviderError(code="PROVIDER_HTTP_ERROR", message=f"{status}: {body[:256]}")
    return json.loads(body or "{}")


def post_json_lines(url: str, payload: dict[str, Any], *, timeout: float) -> Iterator[bytes]:
    begin_direct_model_http()
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            for line in response:
                cleaned = line.strip()
                if cleaned:
                    yield cleaned
    except urllib.error.HTTPError as exc:
        raise ProviderError(code="PROVIDER_STREAM_HTTP_ERROR", message=f"{exc.code}: {exc.read().decode('utf-8')[:256]}") from exc
    except urllib.error.URLError as exc:
        raise ProviderError(code="PROVIDER_STREAM_REQUEST_FAILED", message=str(exc)) from exc
