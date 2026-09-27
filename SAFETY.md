# Safety and ethics

This artifact is an intentionally constrained educational simulation.

- It uses only a seeded repository and a synthetic canary.
- It binds the sink to loopback and rejects non-loopback destinations.
- It makes no LLM/API calls.
- It does not collect real environment-variable values; only names and salted value hashes for explicitly injected lab variables are retained.
- It does not implement persistence, credential theft, destructive actions, or evasion.

Do not repurpose the server to read credentials, contact external systems, or test infrastructure without explicit authorization. In an investigation, apply organizational legal authority, privacy, retention, and chain-of-custody requirements.

