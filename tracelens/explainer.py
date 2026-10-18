"""Optional plain-language notes on survey evidence, from a local Ollama model.

This layer is strictly optional: the evidence review is complete without
it, and nothing ever leaves the machine. The model runs locally (Ollama's
REST API on localhost) and receives only the already-extracted facts and
limitations — never raw packets, payloads, or capture bytes.

The prompt hard-codes the product's evidence rules so the model cannot
talk the report into claiming a root cause or treating absent packets as
proof an event did not happen.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5:1.5b"
DEFAULT_TIMEOUT = 120.0


class ExplainerUnavailable(Exception):
    """Local Ollama is not reachable or refused the request.

    The message is user-facing: it says what to install/start, never a raw
    traceback.
    """


@dataclass
class ExplanationResult:
    """A plain-language note produced by the local model."""

    text: str
    model: str


def build_prompt(analysis: Dict[str, Any]) -> str:
    """Serialize the extracted evidence into a constrained prompt.

    Only the analyzer's output (facts, limitations, notes) is included;
    the capture path is dropped and no packet data is present.
    """
    evidence = {
        "facts": analysis.get("facts", []),
        "limitations": analysis.get("limitations", []),
        "notes": analysis.get("notes", []),
    }
    return (
        "You are writing plain-language survey notes for a Wi-Fi "
        "installer.\n"
        "Below is machine-measured evidence extracted from a packet "
        "capture, as JSON.\n"
        "Write 3-5 short sentences a non-expert can understand, "
        "describing what WAS measured.\n"
        "Hard rules:\n"
        "- Use ONLY the evidence below. If something is not in the "
        "evidence, do not mention it as known.\n"
        "- Missing evidence (an absent packet) is NOT proof an event "
        "did not happen; where a limitation is listed, repeat that the "
        "capture cannot answer that question.\n"
        "- NEVER propose a root cause or a fix; you may ONLY describe "
        "what was measured.\n"
        "- Do not invent numbers, SSIDs, channels, or client "
        "addresses.\n\n"
        "Evidence JSON:\n"
        + json.dumps(evidence, indent=2)
    )


def explain_analysis(
    analysis: Dict[str, Any],
    model: str = DEFAULT_MODEL,
    url: str = DEFAULT_OLLAMA_URL,
    timeout: float = DEFAULT_TIMEOUT,
) -> ExplanationResult:
    """Ask the local Ollama model for plain-language notes on the evidence.

    Raises :class:`ExplainerUnavailable` — with a message telling the user
    what to do — when Ollama is not running, the model is missing, or the
    request fails. Callers treat this feature as optional and fall back to
    showing the evidence alone.
    """
    prompt = build_prompt(analysis)
    payload = json.dumps(
        {"model": model, "prompt": prompt, "stream": False}
    ).encode("utf-8")
    request = urllib.request.Request(
        url.rstrip("/") + "/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        # Ollama reports failures (e.g. unknown model) as JSON bodies with
        # non-200 statuses; surface that message instead of a generic one.
        try:
            body = json.loads(err.read().decode("utf-8"))
        except (OSError, ValueError):
            body = {}
        if "error" in body:
            raise ExplainerUnavailable(
                "Ollama returned an error: {e}".format(e=body["error"])
            ) from err
        raise ExplainerUnavailable(
            "Ollama at {u} answered with HTTP {code}. This feature is "
            "optional: check the model name, or continue with the measured "
            "evidence alone.".format(u=url, code=err.code)
        ) from err
    except urllib.error.URLError as err:
        raise ExplainerUnavailable(
            "Ollama is not reachable at {u} ({reason}). This feature is "
            "optional: install/start Ollama to use it, or continue with "
            "the measured evidence alone.".format(u=url, reason=err.reason)
        ) from err
    except (OSError, ValueError) as err:
        raise ExplainerUnavailable(
            "Could not talk to Ollama at {u}: {err}".format(u=url, err=err)
        ) from err

    if "error" in body:
        raise ExplainerUnavailable(
            "Ollama returned an error: {e}".format(e=body["error"])
        )
    text = str(body.get("response", "")).strip()
    if "</think>" in text:
        text = text.split("</think>", 1)[1].strip()
    if not text:
        raise ExplainerUnavailable(
            "Ollama returned an empty response; try again or use a "
            "different model."
        )
    return ExplanationResult(text=text, model=model)
