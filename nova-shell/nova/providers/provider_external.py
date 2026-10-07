from __future__ import annotations

import json
import time
from typing import Any
from uuid import uuid4

from nova.errors import ProviderError
from nova.receipts import make_receipt
from runtime.call_binding import describe_https
from .http import post_json, refuse_unconfigured_model_http


class ExternalProvider:
    provider_id = "external"

    def __init__(self, *, base_url: str, api_key: str | None, model: str, timeout: float = 60) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def https_call(self, governed_request: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": governed_request.get("messages", []),
            "temperature": governed_request.get("temperature"),
            "max_tokens": governed_request.get("max_tokens"),
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = json.dumps(payload).encode("utf-8")
        return describe_https("POST", f"{self.base_url}/chat/completions", headers, body)

    def completion_from_body(self, governed_request: dict[str, Any], body: bytes) -> dict[str, Any]:
        try:
            data = json.loads(body.decode("utf-8") or "{}")
        except ValueError as exc:
            raise ProviderError(code="EXTERNAL_REQUEST_FAILED", message="the provider did not return JSON") from exc
        if not isinstance(data, dict):
            raise ProviderError(code="EXTERNAL_REQUEST_FAILED", message="the provider did not return an object")
        return self._from_provider_json(governed_request, data)

    def chat_completion(self, governed_request: dict[str, Any]) -> dict[str, Any]:
        refuse_unconfigured_model_http()
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        payload = {
            "model": self.model,
            "messages": governed_request.get("messages", []),
            "temperature": governed_request.get("temperature"),
            "max_tokens": governed_request.get("max_tokens"),
        }
        try:
            data = post_json(f"{self.base_url}/chat/completions", payload, headers=headers, timeout=self.timeout)
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(code="EXTERNAL_REQUEST_FAILED", message=str(exc)) from exc
        return self._from_provider_json(governed_request, data)

    def _from_provider_json(self, governed_request: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
        completion = {
            "id": data.get("id", f"external-{uuid4()}"),
            "object": "chat.completion",
            "created": data.get("created", int(time.time())),
            "model": data.get("model", self.model),
            "choices": data.get("choices", []),
        }
        receipt = make_receipt(
            provider="external",
            model=self.model,
            governed_request=governed_request,
            raw_provider_response=data,
            normalized_completion=completion,
            deterministic_core=False,
            rsl_version="1.0",
            slice_id=governed_request.get("slice_id"),
            slice_version=governed_request.get("slice_version"),
            continuity_hash=governed_request.get("continuity_hash"),
            governance_path=governed_request.get("governance_path", []),
        )
        return {"completion": completion, "receipt": receipt}
