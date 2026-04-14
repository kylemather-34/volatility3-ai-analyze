# This file is part of the Volatility3 AI Analysis feature.
# It calls the Groq API (OpenAI-compatible) to analyse the output of any
# volatility plugin and provide forensic teaching commentary.
#
# Usage:
#   export GROQ_API_KEY=gsk_...
#   python3 vol.py -f image.vmem windows.pslist --analyze
#
# Or pass the key inline:
#   python3 vol.py -f image.vmem windows.pslist --analyze --api-key gsk_...
#
# Override the model (must be available on Groq):
#   python3 vol.py -f image.vmem windows.pslist --analyze --model qwen-qwq-32b
#
# No extra packages required — uses Python's built-in urllib.

from __future__ import annotations

import json
import logging
import os
import sys
import textwrap
import urllib.error
import urllib.request
from typing import Optional

vollog = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Plugin-knowledge: used in the system prompt so the model can make
# contextually-relevant suggestions.  Extend as new plugins are added.
# ---------------------------------------------------------------------------
_PLUGIN_SUGGESTIONS = """
Common Windows volatility3 plugins and what they reveal:
  windows.pslist       - Running processes (PID, PPID, name, start time)
  windows.pstree       - Same as pslist but shows parent/child hierarchy
  windows.psscan       - Scan physical memory for EPROCESS structs (finds hidden procs)
  windows.cmdline      - Command-line arguments for each process
  windows.dlllist      - DLLs loaded by each process
  windows.malfind      - Regions with executable code NOT backed by a file on disk
  windows.handles      - Open handles (files, registry keys, mutexes, ...)
  windows.netscan      - Active / recently-closed network connections
  windows.netstat      - Similar to netscan
  windows.svcscan      - Windows services
  windows.driverscan   - Kernel drivers
  windows.modscan      - Kernel modules
  windows.callbacks    - Registered kernel callbacks (rootkit indicator)
  windows.ssdt         - System Service Descriptor Table hooks
  windows.hollowprocesses - Processes where in-memory image differs from disk
  windows.vadinfo      - Virtual Address Descriptor tree for a process
  windows.envars       - Environment variables per process
  windows.filescan     - FILE_OBJECT structs (open files)
  windows.registry.hivelist  - Loaded registry hives
  windows.registry.printkey  - Print a specific registry key
  windows.hashdump     - Dump password hashes from SAM
  windows.privileges   - Token privileges of each process

Common Linux plugins:
  linux.pslist / linux.pstree
  linux.bash           - Bash history recovered from memory
  linux.netfilter      - Netfilter hooks
  linux.check_syscall  - Syscall table integrity check

When unsure, windows.malfind and windows.netscan are always high-value
follow-up plugins for malware triage.
"""

_MAX_OUTPUT_CHARS = 12_000
_DIVIDER = "=" * 72
_GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------
class AIAnalyzer:
    """Calls the Groq API to produce forensic analysis of volatility output."""

    DEFAULT_MODEL = "llama-3.3-70b-versatile"
    DEFAULT_API_URL = _GROQ_API_URL

    def __init__(self, api_key: str, model: str = DEFAULT_MODEL) -> None:
        self.api_key = api_key
        self.model = model

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _build_system_prompt(plugin_name: str) -> str:
        return textwrap.dedent(f"""
            You are a memory forensics expert and educator specialising in the
            Volatility3 framework.  A student has just run the '{plugin_name}'
            plugin against a memory image and produced the output shown below.

            Your job is to:
            1. Briefly explain what the '{plugin_name}' plugin shows (1-2 sentences).
            2. Identify anything that looks SUSPICIOUS or unusual in the output.
               Be specific — quote process names, PIDs, addresses, paths, etc.
            3. Explain WHY each suspicious item is worth investigating.
            4. Suggest 2-4 follow-up volatility3 plugins the student should run
               next, and explain what each one would reveal about the suspicious
               items you found.

            Keep your answer concise and educational.  Use plain text only — no
            markdown headers or bullet-point symbols, just numbered lists where
            needed.  If nothing looks suspicious, say so clearly and still suggest
            good next steps.

            Reference information about available plugins:
            {_PLUGIN_SUGGESTIONS}
        """).strip()

    def _call_api(self, messages: list) -> str:
        """POST to the Groq chat completions endpoint and return the reply text."""
        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "max_tokens": 1024,
            "temperature": 0.3,
            "top_p": 0.9,
        }).encode()

        req = urllib.request.Request(
            _GROQ_API_URL,
            data=payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "volatility3-ai-analysis/1.0",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise RuntimeError(
                f"Groq API error {exc.code}: {body}"
            ) from exc

        return result["choices"][0]["message"]["content"]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def analyze(self, plugin_name: str, plugin_output: str) -> str:
        """Call the API and return the analysis as a string."""
        truncated = False
        output_to_send = plugin_output
        if len(plugin_output) > _MAX_OUTPUT_CHARS:
            output_to_send = plugin_output[:_MAX_OUTPUT_CHARS]
            truncated = True

        user_message = f"Plugin output for '{plugin_name}':\n\n{output_to_send}"
        if truncated:
            user_message += (
                f"\n\n[Output truncated to {_MAX_OUTPUT_CHARS} characters. "
                f"Full output was {len(plugin_output)} characters.]"
            )

        messages = [
            {"role": "system", "content": self._build_system_prompt(plugin_name)},
            {"role": "user",   "content": user_message},
        ]

        return self._call_api(messages)


# ---------------------------------------------------------------------------
# Convenience function used by the CLI
# ---------------------------------------------------------------------------
def resolve_api_key(cli_key: Optional[str]) -> Optional[str]:
    """Return the API key from the CLI flag or the GROQ_API_KEY env var."""
    return cli_key or os.environ.get("GROQ_API_KEY")


def run_analysis(plugin_name: str, plugin_output: str,
                 api_key: str, model: str) -> None:
    """Run analysis via Groq and print the result to stdout."""
    try:
        analyzer = AIAnalyzer(api_key=api_key, model=model)
        sys.stderr.write(f"[AI] Querying Groq ({model})...\n")
        sys.stderr.flush()
        analysis = analyzer.analyze(plugin_name, plugin_output)
    except Exception as exc:
        vollog.error(f"[ai_analysis] Error: {exc}")
        sys.stderr.write(f"\n[AI Analysis Error] {exc}\n")
        return

    sys.stdout.write(f"\n{_DIVIDER}\n")
    sys.stdout.write(" AI FORENSIC ANALYSIS\n")
    sys.stdout.write(f"{_DIVIDER}\n\n")
    sys.stdout.write(analysis)
    sys.stdout.write(f"\n\n{_DIVIDER}\n")
    sys.stdout.flush()
