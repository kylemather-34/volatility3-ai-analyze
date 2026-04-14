# volatility3-ai-analyze

An AI-powered forensic analysis add-on for [Volatility3](https://github.com/volatilityfoundation/volatility3).

Adds an `--analyze` flag to every plugin. After the plugin output prints, it is sent to the [Groq API](https://console.groq.com) where an LLM highlights suspicious findings and suggests which plugins to run next — making it a practical teaching tool for memory forensics.

```
python3 vol.py -f image.vmem windows.pslist --analyze
```

```
PID    PPID   ImageFileName   ...
--------------------------------------
4      0      System
...
1484   1640   reader_sl.exe   ← suspicious

========================================================================
 AI FORENSIC ANALYSIS
========================================================================

1. The windows.pslist plugin lists all running processes recorded in the
   Windows kernel's doubly-linked EPROCESS list, showing each process's
   PID, parent PID, name, start time, and exit time.

2. Suspicious findings:
   - reader_sl.exe (PID 1484, PPID 1640): Adobe Reader Speed Launcher is
     a legitimate process, but its parent (PID 1640) is explorer.exe.
     Malware frequently masquerades as trusted names. Worth verifying the
     full image path and whether it has network connections.
   - Two cmd.exe instances (PID 1720, 1640) running under explorer.exe
     with almost identical start times suggest automated shell spawning.

3. Recommended follow-up plugins:
   - windows.cmdline  — see the exact command-line arguments for the
     suspicious cmd.exe and reader_sl.exe processes.
   - windows.netscan  — check whether any of these processes have active
     or recently closed network connections.
   - windows.malfind  — scan for executable memory regions not backed by
     a file on disk, a common indicator of code injection.
   - windows.dlllist  — inspect which DLLs reader_sl.exe has loaded; an
     injected DLL will stand out against the expected Adobe libraries.

========================================================================
```

---

## Requirements

- Python 3.8+
- An existing [Volatility3](https://github.com/volatilityfoundation/volatility3) installation
- A free [Groq API key](https://console.groq.com) (no credit card required)

No extra Python packages are needed — the API call uses Python's built-in `urllib`.

---

## Installation

Clone this repo, then run the install script from the root of your volatility3 directory:

```bash
git clone https://github.com/kylemather-34/volatility3-ai-analyze.git
cd /path/to/your/volatility3
bash /path/to/volatility3-ai-analyze/install.sh
```

The script:
1. Copies `ai_analysis.py` into `volatility3/framework/`
2. Applies `cli_analyze.patch` to `volatility3/cli/__init__.py`

### Manual installation

If the install script doesn't work (e.g. your `cli/__init__.py` has diverged), do it by hand:

```bash
# 1. Copy the module
cp ai_analysis.py /path/to/volatility3/volatility3/framework/ai_analysis.py

# 2. Apply the patch
cd /path/to/volatility3
patch -p1 < /path/to/volatility3-ai-analyze/cli_analyze.patch
```

---

## Setup

Get your free API key at [console.groq.com](https://console.groq.com), then export it:

```bash
export GROQ_API_KEY=gsk_...
```

Add that line to your `~/.zshrc` or `~/.bashrc` so you don't have to type it each session.

---

## Usage

Append `--analyze` to any volatility3 command:

```bash
# Process list
python3 vol.py -f image.vmem windows.pslist --analyze

# Network connections
python3 vol.py -f image.vmem windows.netscan --analyze

# Suspicious memory regions
python3 vol.py -f image.vmem windows.malfind --analyze

# Linux memory image
python3 vol.py -f image.lime linux.pslist --analyze
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--analyze` | off | Enable AI analysis after plugin output |
| `--api-key KEY` | `$GROQ_API_KEY` | Groq API key (env var preferred) |
| `--model NAME` | `llama-3.3-70b-versatile` | Groq model to use |

### Choosing a model

Any model available on Groq works. Some options:

| Model | Speed | Notes |
|-------|-------|-------|
| `llama-3.3-70b-versatile` | Fast | Default, great reasoning |
| `llama-3.1-8b-instant` | Very fast | Lighter, good for quick triage |
| `qwen-qwq-32b` | Fast | Strong reasoning, Qwen series |

```bash
python3 vol.py -f image.vmem windows.pslist --analyze --model qwen-qwq-32b
```

---

## How it works

1. The plugin runs normally and its output is printed to the terminal as usual.
2. The output is simultaneously captured in memory.
3. After rendering completes, the captured text is sent to the Groq API with a forensics-focused system prompt.
4. The model's response is printed in a clearly delimited block below the plugin output.

The system prompt instructs the model to:
- Explain what the plugin shows
- Identify specific suspicious entries (by name, PID, address, path)
- Explain why each finding is worth investigating
- Suggest 2–4 follow-up Volatility3 plugins

Output larger than ~12,000 characters is truncated before sending to stay within the model's context window.

---

## Files

| File | Purpose |
|------|---------|
| `ai_analysis.py` | Core module — API client, prompt builder, output formatter |
| `cli_analyze.patch` | Git patch for `volatility3/cli/__init__.py` |
| `install.sh` | Automated install script |

---

## Privacy note

Plugin output (which may contain process names, file paths, registry keys, and other artefacts from the memory image) is sent to Groq's servers for inference. Do not use `--analyze` on memory images from sensitive investigations where data must remain on-premises.

---

## License

MIT
