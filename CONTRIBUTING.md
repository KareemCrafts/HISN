# Contributing to HISN

Thank you for your interest in contributing to HISN.

## Ways to Contribute

- 🐛 **Bug Reports** — Open an issue with reproduction steps
- 💡 **Feature Requests** — Open a discussion first
- 🔧 **Pull Requests** — See guidelines below
- 📖 **Documentation** — Always welcome
- 🎯 **Detection Rules** — New Sigma rules or baseline rules

## Pull Request Guidelines

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes with clear commit messages
4. Test locally with at least one sample .evtx file
5. Ensure no Python exceptions on startup
6. Open a PR with a clear description

## Detection Rule Contributions

New baseline rules go in `src/detection/engine.py` → `BASELINE_RULES`.
They need:
- `rule_name`: descriptive string
- `event_id`: Windows Event ID (integer or string)
- `mitre_technique_id`: MITRE technique (e.g., "T1059.001")
- `mitre_technique_name`: Full technique name
- `mitre_tactic`: MITRE tactic
- `severity`: critical/high/medium/low/informational
- `confidence`: 0.0–1.0

## Code Style

- Python: follow PEP 8, type hints where practical
- JS: vanilla only (no frameworks), preserve the BLACK SITE aesthetic
- No external CSS/JS CDNs (except Google Fonts)
