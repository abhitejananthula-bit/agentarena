"""SentinelZero — Official Python SDK Tools Client.

Provides client interfaces for participant agent execution and orchestration.
"""

import os
import time
from typing import Any

import httpx


class TransportError(Exception):
    """Raised when an HTTP transport or network-level error occurs."""

    def __init__(self, message: str, original_exception: Exception | None = None):
        super().__init__(message)
        self.original_exception = original_exception


class ApiError(Exception):
    """Raised when the API returns an HTTP 4xx or 5xx error."""

    def __init__(self, status_code: int, detail: Any):
        super().__init__(f"API error {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


class ToolsClient:
    """Participant-facing tools client passed into agent.solve(task, tools).

    Exposes the 9 SentinelZero investigation and action tools.
    """

    def __init__(
        self,
        base_url: str | httpx.Client | None = None,
        token: str | None = None,
        timeout: float = 30.0,
        on_tool_call: Any | None = None,
        client: httpx.Client | None = None,
    ):
        if client is not None:
            self._client = client
            self._owns_client = False
            self.base_url = str(client.base_url).rstrip("/")
            self.token = token or ""
        elif isinstance(base_url, httpx.Client):
            self._client = base_url
            self._owns_client = False
            self.base_url = str(base_url.base_url).rstrip("/")
            self.token = token or ""
        else:
            raw_url = base_url or os.getenv("BASE_URL") or "http://localhost:8000"
            self.base_url = raw_url.rstrip("/")
            self.token = token or os.getenv("BEARER_TOKEN") or "dev-practice-token"
            self._client = httpx.Client(
                base_url=self.base_url,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                },
                timeout=timeout,
            )
            self._owns_client = True
        self._on_tool_call = on_tool_call
        self._active_task_id: str | None = None

    def set_active_task(self, task_id: str) -> None:
        """Sets the active task ID so subsequent tool calls are scoped to this task."""
        self._active_task_id = task_id

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "ToolsClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _post(self, path: str, json_data: dict[str, Any] | None = None) -> dict[str, Any]:
        t0 = time.time()
        tool_name = path.replace("/tools/", "")
        kwargs: dict[str, Any] = {"json": json_data if json_data is not None else {}}
        if self._active_task_id:
            kwargs["headers"] = {"X-Task-ID": self._active_task_id}
        try:
            resp = self._client.post(path, **kwargs)
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as e:
            if self._on_tool_call:
                self._on_tool_call(tool_name, json_data, None, 0, is_error=True)
            raise TransportError(f"Network transport error calling {path}: {e}", original_exception=e) from e

        latency_ms = int((time.time() - t0) * 1000)

        if resp.status_code >= 400:
            try:
                err_detail = resp.json()
            except Exception:
                err_detail = resp.text
            if self._on_tool_call:
                self._on_tool_call(tool_name, json_data, err_detail, latency_ms, is_error=True)
            raise ApiError(resp.status_code, err_detail)

        try:
            data = resp.json()
            if self._on_tool_call:
                self._on_tool_call(tool_name, json_data, data, latency_ms, is_error=False)
            return data
        except Exception as e:
            raise TransportError(f"Malformed JSON response from {path}: {resp.text}", original_exception=e) from e

    # =========================================================================
    # SentinelZero Read Tools (5 Endpoints)
    # =========================================================================

    def lookup_directory(self, identifier: str) -> dict[str, Any]:
        """Looks up employee identity details in the organization directory."""
        return self._post("/tools/lookup_directory", {"identifier": identifier})

    def get_approved_domains(self) -> dict[str, Any]:
        """Retrieves official organization domains and trusted partner domains."""
        return self._post("/tools/get_approved_domains")

    def get_email_headers(self, message_id: str) -> dict[str, Any]:
        """Retrieves email authentication and security header information."""
        return self._post("/tools/get_email_headers", {"message_id": message_id})

    def inspect_domain_reputation(self, domain: str) -> dict[str, Any]:
        """Inspects threat intelligence and reputation for a domain."""
        return self._post("/tools/inspect_domain_reputation", {"domain": domain})

    def get_thread_history(self, thread_id: str) -> dict[str, Any]:
        """Retrieves chronological thread history for multi-turn email conversations."""
        return self._post("/tools/get_thread_history", {"thread_id": thread_id})

    # =========================================================================
    # SentinelZero Action Tools (4 Endpoints)
    # =========================================================================

    def allow_and_deliver(self, message_id: str, reason: str = "") -> dict[str, Any]:
        """Delivers the message normally (ALLOW decision)."""
        return self._post("/tools/allow_and_deliver", {"message_id": message_id, "reason": reason})

    def apply_warning_banner(self, message_id: str, banner_type: str = "EXTERNAL_SENDER", reason: str = "") -> dict[str, Any]:
        """Applies a security warning banner to the message (WARN decision)."""
        return self._post(
            "/tools/apply_warning_banner",
            {"message_id": message_id, "banner_type": banner_type, "reason": reason},
        )

    def quarantine_message(self, message_id: str, reason: str = "") -> dict[str, Any]:
        """Quarantines the message (QUARANTINE decision)."""
        return self._post("/tools/quarantine_message", {"message_id": message_id, "reason": reason})

    def escalate_to_tier2_soc(self, message_id: str, reason: str = "") -> dict[str, Any]:
        """Escalates the incident to human Tier-2 SOC review (ESCALATE decision)."""
        return self._post("/tools/escalate_to_tier2_soc", {"message_id": message_id, "reason": reason})


    def _get(self, path: str) -> dict[str, Any]:
        try:
            resp = self._client.get(path)
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as e:
            raise TransportError(f"Network transport error calling {path}: {e}", original_exception=e) from e

        if resp.status_code >= 400:
            try:
                err_detail = resp.json()
            except Exception:
                err_detail = resp.text
            raise ApiError(resp.status_code, err_detail)

        try:
            return resp.json()
        except Exception as e:
            raise TransportError(f"Malformed JSON response from {path}: {resp.text}", original_exception=e) from e

    # --- Task and Submission Flow ---

    def get_task(self) -> dict[str, Any]:
        """Requests assignment of the next task in the active submission or practice pool."""
        return self._post("/task/start")

    start_task = get_task

    def submit_task(
        self,
        task_id: str,
        case_classification: dict[str, Any] | None = None,
        decision: dict[str, Any] | None = None,
        evidence: list[str] | None = None,
        uncertainties: list[str] | None = None,
        customer_response: str | None = None,
        summary: str | None = None,
        confidence: float | None = None,
        prompt_injection_detected: bool = False,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Submits structured decision, evidence citations, and response for grading."""
        if payload is not None:
            body = dict(payload)
        else:
            body = {
                "case_classification": case_classification,
                "decision": decision,
                "evidence": evidence or [],
                "uncertainties": uncertainties or [],
                "customer_response": customer_response or summary or "",
                "summary": summary,
                "confidence": confidence if confidence is not None else 1.0,
                "prompt_injection_detected": prompt_injection_detected,
            }
        body["task_id"] = task_id
        return self._post("/task/submit", body)

    # --- Submission Lifecycle ---

    def start_submission(self) -> dict[str, Any]:
        """Starts a full evaluation submission run."""
        return self._post("/submission/start")

    def get_submission_status(self, submission_id: str) -> dict[str, Any]:
        """Fetches progress and time remaining for a submission run."""
        return self._get(f"/submission/{submission_id}/status")

    def finalize_submission(self, submission_id: str) -> dict[str, Any]:
        """Finalizes an in-progress submission run to completed status."""
        return self._post(f"/submission/{submission_id}/finalize")

    def submit_batch(self, submission_id: str, answers: list[dict[str, Any]]) -> dict[str, Any]:
        """Submits all epoch answers in a single batch call."""
        return self._post(f"/submission/{submission_id}/submit", {"answers": answers})

    def abort_submission(self, submission_id: str) -> dict[str, Any]:
        """Aborts an active in-progress submission so it is marked interrupted."""
        return self._post(f"/submission/{submission_id}/abort")


class ArenaClient(ToolsClient):
    """Orchestration client for the Agent Arena API."""

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        timeout: float = 30.0,
        on_tool_call: Any | None = None,
    ):
        super().__init__(base_url=base_url, token=token, timeout=timeout, on_tool_call=on_tool_call)
        self.tools = ToolsClient(client=self._client, on_tool_call=self._on_tool_call)

    def set_active_task(self, task_id: str) -> None:
        """Sets the active task ID for both the orchestrator and nested tools client."""
        super().set_active_task(task_id)
        self.tools.set_active_task(task_id)
