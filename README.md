# Project GIDEON

> **G**eneral **I**ntelligent **D**istributed **E**xecution and **O**rchestration **N**etwork  
> A local-first, distributed personal AI agent — built for privacy and extensibility.

---

## Status

🚧 **Pre-alpha** — foundational scaffolding only. No AI/LLM integration yet.

---

## Quick Start

### Prerequisites

- Python **3.13+**
- `pip` or `uv`

### 1. Clone

```bash
git clone https://github.com/your-org/Project-GIDEON.git
cd Project-GIDEON
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
```

### 3. Install (editable)

```bash
pip install -e ".[dev]"
```

### 4. Configure

```bash
cp .env.example .env
# Edit .env with your preferred settings
```

### 5. Run

```bash
gideon
# or
python -m gideon
```

---

## Project Layout

```
Project-GIDEON/
├── src/
│   └── gideon/
│       ├── __init__.py
│       ├── __main__.py        # CLI entry point
│       └── core/
│           ├── __init__.py
│           ├── config.py      # Configuration via env vars
│           ├── logging.py     # Structured logging setup
│           └── health.py      # Health / status object
├── tests/
│   ├── __init__.py
│   └── core/
│       ├── __init__.py
│       ├── test_config.py
│       ├── test_logging.py
│       └── test_health.py
├── .env.example
├── .gitignore
├── pyproject.toml
└── README.md
```

---

## Running Tests

```bash
pytest
# With coverage:
pytest --cov=gideon --cov-report=term-missing
```

---

## Configuration

All settings are read from environment variables (or a `.env` file).

| Variable           | Default       | Description                              |
|--------------------|---------------|------------------------------------------|
| `GIDEON_ENV`       | `development` | Runtime environment label                |
| `GIDEON_AGENT_NAME`| `GIDEON`      | Friendly agent name                      |
| `GIDEON_LOG_LEVEL` | `INFO`        | Logging level (`DEBUG`…`CRITICAL`)       |
| `GIDEON_LOG_FORMAT`| `text`        | Log format — `text` or `json`            |
| `GIDEON_LOG_FILE`  | *(empty)*     | Optional log file path; blank = stdout   |

---

## License

MIT