"""HTTP target adapter — connects to any REST API and auto-detects the format."""

import json
import re
import requests
from typing import Union, List, Dict, Any, Optional
from chimera.targets.base import BaseTarget
from chimera.core.target_manager import TargetManager


class HTTPTarget(BaseTarget):
    """Universal HTTP target — auto-detects any REST API format."""

    def __init__(self, model_id: str, **kwargs):
        # Parse URI: base_url::key=val::key=val
        parts = model_id.split("::")
        self.base_url = parts[0].rstrip("/")
        self.extra_headers: Dict[str, str] = {}
        self.extra_params: Dict[str, str] = {}

        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                k_lower = k.lower()
                if k_lower in ("authorization", "x-api-key", "api-key",
                               "bearer", "token", "hf-token", "x-auth-token"):
                    self.extra_headers[k] = v
                else:
                    self.extra_params[k] = v

        self.connect_timeout = 8    # seconds to establish connection
        self.read_timeout = 90      # seconds to read response (Lumen has thinking pipeline)
        self.detected_format: Optional[str] = None
        self.detected_endpoint: Optional[str] = None
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})
        self._session.headers.update(self.extra_headers)

        super().__init__(model_id=self.base_url, **{k: v for k, v in kwargs.items()})

    def _load_model(self, **kwargs) -> None:
        self._detect_format()

    def _post(self, path: str, body: dict) -> requests.Response:
        url = self.base_url + path if path else self.base_url
        return self._session.post(
            url, json=body,
            timeout=(self.connect_timeout, self.read_timeout)
        )

    def _get(self, path: str) -> requests.Response:
        url = self.base_url + path if path else self.base_url
        return self._session.get(url, timeout=(self.connect_timeout, self.read_timeout))

    def _consume_sse(self, response: requests.Response) -> str:
        """Consume an SSE stream and return concatenated text."""
        chunks = []
        for raw in response.iter_lines(decode_unicode=True):
            if not raw or raw.startswith(":"):
                continue
            if raw.startswith("data:"):
                payload = raw[5:].strip()
                if payload in ("[DONE]", "[done]", ""):
                    break
                if payload.startswith("[ERROR]"):
                    break
                try:
                    d = json.loads(payload)
                    text = (d.get("text") or d.get("content") or
                            d.get("token") or d.get("delta") or
                            (d.get("choices") or [{}])[0].get("delta", {}).get("content") or
                            (d.get("choices") or [{}])[0].get("text") or "")
                    if text:
                        chunks.append(str(text))
                except Exception:
                    if payload:
                        chunks.append(payload)
        return "".join(chunks)

    def _extract_text(self, data: Any) -> str:
        """Extract text from any JSON response structure."""
        if isinstance(data, str):
            return data
        if isinstance(data, list) and data:
            return self._extract_text(data[0])
        if isinstance(data, dict):
            for key in ["response", "text", "output", "result", "answer",
                        "message", "content", "generated_text", "reply",
                        "completion", "assistant", "bot"]:
                if key in data:
                    v = data[key]
                    if isinstance(v, str):
                        return v
                    if isinstance(v, dict):
                        return self._extract_text(v)
            # OpenAI choices
            if "choices" in data and data["choices"]:
                c = data["choices"][0]
                return (c.get("message", {}).get("content") or
                        c.get("text") or str(c))
            # Nested dict — return first string value
            for v in data.values():
                if isinstance(v, str) and len(v) > 3:
                    return v
        return str(data)

    def _detect_format(self) -> None:
        """Probe the API to find the right format. Fast, with short timeouts."""
        probe = "Hi"
        old_read = self.read_timeout
        self.read_timeout = 10  # fast probe

        # 1. SSE streaming (Lumen-style: POST /api/v1/completions)
        for path in ["/api/v1/completions", "/v1/completions", "/api/completions"]:
            try:
                r = self._session.post(
                    self.base_url + path,
                    json={"prompt": probe},
                    timeout=(self.connect_timeout, self.read_timeout),
                    stream=True
                )
                if r.status_code == 200:
                    ct = r.headers.get("content-type", "")
                    if "event-stream" in ct or "text/plain" in ct:
                        # Confirmed SSE endpoint
                        self.detected_format = "sse_completions"
                        self.detected_endpoint = path
                        self.read_timeout = old_read
                        return
                    # Try consuming anyway
                    text = self._consume_sse(r)
                    if text:
                        self.detected_format = "sse_completions"
                        self.detected_endpoint = path
                        self.read_timeout = old_read
                        return
            except Exception:
                pass

        # 2. OpenAI-compatible
        for path in ["/v1/chat/completions", "/api/v1/chat/completions", "/chat/completions"]:
            try:
                r = self._post(path, {
                    "model": self.extra_params.get("model", "default"),
                    "messages": [{"role": "user", "content": probe}],
                    "max_tokens": 5
                })
                if r.status_code == 200:
                    d = r.json()
                    if "choices" in d:
                        self.detected_format = "openai"
                        self.detected_endpoint = path
                        self.read_timeout = old_read
                        return
            except Exception:
                pass

        # 3. HuggingFace Inference API
        for path in ["", "/api/predict"]:
            try:
                r = self._post(path, {"inputs": probe, "parameters": {"max_new_tokens": 5}})
                if r.status_code == 200:
                    d = r.json()
                    if isinstance(d, list) and d and "generated_text" in d[0]:
                        self.detected_format = "hf_inference"
                        self.detected_endpoint = path
                        self.read_timeout = old_read
                        return
            except Exception:
                pass

        # 4. Gradio
        for path in ["/run/predict", "/api/predict"]:
            try:
                r = self._post(path, {"data": [probe]})
                if r.status_code == 200 and "data" in r.json():
                    self.detected_format = "gradio"
                    self.detected_endpoint = path
                    self.read_timeout = old_read
                    return
            except Exception:
                pass

        # 5. Generic JSON — try common field names and paths
        for path in ["/api/chat", "/chat", "/api/generate", "/generate",
                     "/api/message", "/api/ask", "/api/query", "/api", ""]:
            for body in [{"message": probe}, {"prompt": probe},
                         {"query": probe}, {"input": probe},
                         {"messages": [{"role": "user", "content": probe}]}]:
                try:
                    r = self._post(path, body)
                    if r.status_code == 200 and len(r.text) > 3:
                        self.detected_format = "generic"
                        self.detected_endpoint = path
                        self._probe_body_key = list(body.keys())[0]
                        self.read_timeout = old_read
                        return
                except Exception:
                    pass

        # Fallback
        self.detected_format = "generic"
        self.detected_endpoint = ""
        self._probe_body_key = "message"
        self.read_timeout = old_read

    def _clean_response(self, text: str) -> str:
        """Strip internal status tokens from streaming responses."""
        # Remove Lumen-style status tokens
        text = re.sub(
            r'\b(STREAMING|SYNCING|READY|INITIALIZING|KERNEL_LOAD|THINKING|'
            r'Analyzing[^.]*\.\.\.|Resolving[^.]*\.\.\.|Optimizing[^.]*\.\.\.|'
            r'Cross-referencing[^.]*\.\.\.|Verifying[^.]*\.\.\.)\b',
            '', text
        )
        return text.strip()

    def generate(self, prompt: Union[str, List[Dict]], **kwargs) -> str:
        """Send prompt to target and return response."""
        if isinstance(prompt, list):
            text = " ".join(m.get("content", "") for m in prompt if isinstance(m, dict))
        else:
            text = str(prompt)

        fmt = self.detected_format or "generic"
        path = self.detected_endpoint or ""

        try:
            if fmt == "sse_completions":
                r = self._session.post(
                    self.base_url + path,
                    json={"prompt": text},
                    timeout=(self.connect_timeout, self.read_timeout),
                    stream=True
                )
                r.raise_for_status()
                return self._clean_response(self._consume_sse(r))

            elif fmt == "openai":
                r = self._post(path, {
                    "model": self.extra_params.get("model", "default"),
                    "messages": [{"role": "user", "content": text}],
                    "max_tokens": kwargs.get("max_tokens",
                                            getattr(self, "_default_max_tokens", 512)),
                    "temperature": kwargs.get("temperature", 0.7),
                })
                r.raise_for_status()
                d = r.json()
                return (d.get("choices", [{}])[0]
                        .get("message", {}).get("content", self._extract_text(d)))

            elif fmt == "hf_inference":
                r = self._post(path, {
                    "inputs": text,
                    "parameters": {"max_new_tokens": kwargs.get("max_tokens", 256)}
                })
                r.raise_for_status()
                d = r.json()
                if isinstance(d, list):
                    return d[0].get("generated_text", text)
                return d.get("generated_text", self._extract_text(d))

            elif fmt == "gradio":
                r = self._post(path, {"data": [text]})
                r.raise_for_status()
                d = r.json()
                data = d.get("data", [])
                return data[0] if data else self._extract_text(d)

            else:  # generic
                key = getattr(self, "_probe_body_key", "message")
                body: Dict[str, Any] = {key: text}
                if key == "messages":
                    body = {"messages": [{"role": "user", "content": text}]}
                r = self._post(path, body)
                r.raise_for_status()
                return self._extract_text(r.json())

        except requests.exceptions.Timeout:
            return "[HTTPTarget: request timed out]"
        except requests.exceptions.ConnectionError as e:
            return f"[HTTPTarget: connection error — {e}]"
        except Exception as e:
            return f"[HTTPTarget: {e}]"


# Register
TargetManager.register_target("http", HTTPTarget)
TargetManager.register_target("https", HTTPTarget)
