# Contributing

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest --cov
python tools/evaluate.py          # compares with dkimpy, pyspf and cryptography
python tools/live_check.py        # needs working DNS
```

- **One runtime dependency (`dnspython`).** DKIM maths, SPF, DMARC and parsing are standard library.
- **Everything above the resolver runs offline** against `StaticResolver` (a dict or a JSON zone file). New tests should too.
- **Never let git change line endings of `.eml` files** (`.gitattributes` handles it): DKIM signs CRLF.
- **A new finding** goes in `analyze._findings` with a severity and a stable `code`, and needs a test in `tests/test_analyze.py`.
- **Report what could not be checked as such** (`temperror`, `permerror`, "not checked"), never as a pass or a fail.
- The sample messages are regenerated with `python tools/make_examples.py` (new keys each time: commit `examples/` as a whole).
