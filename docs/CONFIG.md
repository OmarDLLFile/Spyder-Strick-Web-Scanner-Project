# Configuration

## CLI

```
python main.py -u http://localhost:8000 --depth 2 --intensity medium --authorize
python main.py -u https://target.example --authorize --allow api.target.example
python main.py -u http://localhost:8000 --sast ./myapp
python main.py -u http://localhost:8000 --ai-provider ollama --ai-model llama3.1
python main.py --dashboard
python main.py --serve --serve-port 8080
python main.py --list-scans
```

## YAML config

`python main.py --config config.yaml` — see `config.example.yaml` in the repo root.
CLI flags override YAML values.

## Authorization / scope

- Local targets (`localhost`, `127.0.0.1`, `*.test`, `*.local`) scan without a flag.
- Any other target requires `--authorize`. Use it only with written permission.
- `--allow host` adds extra in-scope hosts. Every request is scope-checked in
  `core/requester.py`; out-of-scope requests raise `PermissionError`.

## AI configuration

| Setting | Meaning |
|---|---|
| `--ai-provider none` (default) | AI disabled; traditional scanning is fully independent |
| `--ai-provider ollama` | Local model via `http://localhost:11434` (default `--ai-base-url`) |
| `--ai-provider openai` | Any OpenAI-compatible API; key from env `AI_API_KEY` only |
| `--ai-model` | Model name, e.g. `llama3.1`, `gpt-4o-mini` |
| `--ai-base-url` | Provider base URL |

AI never marks a finding `confirmed` (capped at `strong`), never executes
commands, and prompts are secret-redacted with untrusted app content wrapped
in `<APP_DATA>` delimiters. Audit log: `reports/ai_audit.log.jsonl` (no secrets).

No API keys, passwords or tokens are ever committed. `AI_API_KEY` is read from
the environment at runtime only.
