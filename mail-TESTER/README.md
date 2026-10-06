# Mail Tester

Email deliverability and phishing analysis tool for the **Hook, Line, and Sinker 2.0** security training.

Send emails via SMTP or upload `.eml` files to get a score (0-10) with SPF/DKIM/DMARC checks, content analysis, AI-powered phishing detection, interactive chat, and red-team attack surface reports.

## Quick Start (local)

```bash
cp .env.example .env   # edit with your settings
make install
make run
```

Ports are configured in `.env` (`MAILTESTER_WEB_PORT`, `MAILTESTER_SMTP_PORT`).

## Quick Start (Docker)

Ollama runs on your host machine; the container connects to it via `host.docker.internal`.

```bash
cp .env.example .env

# Edit .env:
#   MAILTESTER_LLM_PROVIDER=ollama
#   MAILTESTER_LLM_MODEL=qwen3.5:35b

# Make sure Ollama is running with your model pulled
ollama pull qwen3.5:35b

make docker-build
make docker-up
make docker-logs      # verify startup
```

Set `MAILTESTER_LLM_PROVIDER=none` in `.env` to run without AI features.

## Usage

**Send a test email:** (port from `MAILTESTER_SMTP_PORT` in `.env`)
```bash
swaks --to test@mail-tester.phishing.click \
      --from student@example.com \
      --server localhost:2525
```

**Upload a .eml file:** drag and drop on the home page or go to `/upload`.

**Spoofing simulator:** go to `/simulate`, upload an `.eml`, and override the From domain / sending IP to test "will it land?" scenarios.

**AI chat:** ask questions about any analysis result on its detail page.

## Configuration

All settings are in `.env` (see `.env.example` for the full list). Key variables:

| Variable | Default | Description |
|---|---|---|
| `MAILTESTER_WEB_PORT` | `31337` | Web server port |
| `MAILTESTER_SMTP_PORT` | `2525` | SMTP server port |
| `MAILTESTER_SMTP_DOMAIN` | `mail-tester.phishing.click` | Domain shown in SMTP instructions |
| `MAILTESTER_LLM_PROVIDER` | `none` | `none`, `ollama`, `openai`, `anthropic`, `malwarebytes` |
| `MAILTESTER_LLM_MODEL` | | Model name for the chosen provider |
| `MAILTESTER_OLLAMA_URL` | `http://localhost:11434` | Ollama endpoint (in Docker, auto-set to `host.docker.internal`) |

## Makefile

| Command | Description |
|---|---|
| `make install` | Create venv and install dependencies |
| `make run` | Start the app |
| `make test` | Run tests |
| `make docker-build` | Build Docker image |
| `make docker-up` / `docker-down` | Start / stop containers |
| `make docker-logs` | Tail container logs |

## Troubleshooting

**Docker can't reach host Ollama:** Ollama defaults to `localhost` only, so the container can't reach it via `host.docker.internal`. Restart Ollama on all interfaces:

```bash
# CLI
OLLAMA_HOST=0.0.0.0 ollama serve

# macOS app (then restart the app)
launchctl setenv OLLAMA_HOST "0.0.0.0"
```

On Linux, `host.docker.internal` is resolved via `extra_hosts` in `docker-compose.yml`.

**Uploaded .eml scores low:** expected -- DKIM signatures break in stored files and SPF can't verify without the original sending IP. The scorer compensates using `Authentication-Results` headers.
