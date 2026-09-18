# Trusted package baseline

Generated automatically from project lockfiles: **not** a manual allowlist.

Rebuild:

```bash
curl -X POST http://127.0.0.1:8000/v1/trust/baseline/rebuild
```

Or from Python:

```bash
cd backend && python -c "from app.services.baseline_builder import save_baseline; print(save_baseline())"
```

Sources (default):

- `demo-site/package-lock.json`
- `demo-site/lab-victim-dep-confusion/safe/package-lock.json`
- `demo-site/lab-victim-typo-only/package-lock.json`
