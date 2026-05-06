# Test fixtures

## sample_breach_data.csv

**This file is synthetic. Every row is fake.**

* All e-mail addresses use `example.invalid`, a domain reserved by
  RFC 6761 §6.4 specifically so that no live recipient can ever
  receive mail at any address inside it.
* Every SHA-1 is the hash of a synthetic label of the form
  `synthetic-<word>-<index>` — the underlying string is *not* a real
  password and is documented in `scripts/regenerate_fixture.py`
  inside this repo's history.
* The `source` column is filled with deliberately unreal corpus names
  (`SyntheticCorpus2023`, `ResearchCorpusA`, etc.) so an automated
  scanner can never confuse this fixture with real breach data.

The file exists to give the cross-reference module
(`scanner/breach_csv.py`) a deterministic source for tests, the eval
harness, and end-to-end demos. **Do not extend it with real breach
records.** If you need to test against real records during a paid
engagement, point `--csv` at your own out-of-tree dataset.
