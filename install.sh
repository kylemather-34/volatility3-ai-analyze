#!/usr/bin/env bash
# install.sh — integrate volatility3-ai-analyze into an existing volatility3 repo
#
# Usage:
#   cd /path/to/your/volatility3
#   bash /path/to/volatility3-ai-analyze/install.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Sanity check ─────────────────────────────────────────────────────────────
if [[ ! -f "vol.py" ]]; then
  echo "ERROR: Run this script from the root of your volatility3 directory."
  echo "       e.g.  cd ~/volatility3 && bash $SCRIPT_DIR/install.sh"
  exit 1
fi

# ── 1. Copy the AI analysis module ───────────────────────────────────────────
echo "→ Copying ai_analysis.py …"
cp "$SCRIPT_DIR/ai_analysis.py" volatility3/framework/ai_analysis.py
echo "  Done."

# ── 2. Apply the CLI patch ────────────────────────────────────────────────────
echo "→ Applying CLI patch …"
if git apply --check "$SCRIPT_DIR/cli_analyze.patch" 2>/dev/null; then
  git apply "$SCRIPT_DIR/cli_analyze.patch"
  echo "  Done."
else
  echo "  WARNING: patch did not apply cleanly (your cli/__init__.py may have"
  echo "  diverged from the version this patch targets)."
  echo "  Apply it manually:  patch -p1 < $SCRIPT_DIR/cli_analyze.patch"
fi

echo ""
echo "✓ Installation complete."
echo ""
echo "Next steps:"
echo "  1. Get a free Groq API key at https://console.groq.com"
echo "  2. export GROQ_API_KEY=gsk_..."
echo "  3. python3 vol.py -f image.vmem windows.pslist --analyze"
