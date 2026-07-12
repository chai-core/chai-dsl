# Detector evaluation (AFC layer)

Like `BENCHMARKS.md` for performance, this is the **only** place for detector
accuracy numbers, and every figure here comes from a real run that is
reproducible by the commands below. Nothing is hand-tuned or fabricated.

## DLP / PII: Microsoft Presidio (live)

We evaluate the **real** Presidio analyzer (`en_core_web_lg`) end-to-end through
our production `PresidioDetector` adapter (`src/afc.rs`). The Python step runs
Presidio and records its *native* JSON output per case; the Rust step replays
that exact body through `PresidioDetector::detect` → `parse_presidio` and scores
the surfaced `dlp_facts` against ground truth. So both the detector and our
adapter are measured, with no mocking.

Dataset: 460 seeded, templated cases (360 with one planted PII entity across 9
Presidio types, 100 clean). Synthetic/templated with Faker is the standard PII
eval approach (cf. `microsoft/presidio-research`); seeding makes it
reproducible. It measures the Presidio+adapter pipeline on this distribution;
it is **not** a claim of production accuracy on arbitrary real text.

**What this number is (and isn't).** The headline F1 is predominantly *Presidio's*
detection accuracy on this distribution, i.e. the tool's quality, not ours. What
it validates for *our* code is the **integration**: that `PresidioDetector` /
`parse_presidio` correctly consume Presidio's *real* native output (multiple
entities, scores, the spurious `DATE_TIME`), not just hand-written fixtures,
and surface the right `dlp_facts`. Detector *accuracy* belongs to the tool;
*correct integration + fail-closed handling* is what we own and test.

### Results (threshold `pii_confidence ≥ 0.50`, `en_core_web_lg`)

```
Detection (any-PII present?), raw adapter confidence stream:
  precision 88.8%   recall 87.8%   F1 88.3%   (TP 316 FP 40 FN 44 TN 60)

Entity-type (micro, over the 9 target types):
  precision 76.5%   recall 85.8%   F1 80.9%   (TP 309 FP 95 FN 51)

Per-type recall on planted entities:
  PERSON         100.0%   EMAIL_ADDRESS  100.0%   US_SSN     100.0%
  IP_ADDRESS     100.0%   URL            100.0%   IBAN_CODE  100.0%
  PHONE_NUMBER    80.0%   CREDIT_CARD     75.0%   LOCATION    17.5%
```

### Honest reading of the numbers

These are real Presidio behaviors, not adapter bugs:

* **`LOCATION` recall 17.5%**: spaCy `en_core_web_lg` NER misses most Faker
  city names (and some Faker cities are non-words like "Carloshaven"). This is
  the dominant recall drag and a known Presidio/NER limitation.
* **`PHONE_NUMBER` / `CREDIT_CARD` < 100%**: extension-style numbers
  (`296-763-1931x4919`) and some card formats fall below Presidio's own
  confidence threshold or aren't matched.
* **False positives are mostly `DATE_TIME`**: Presidio aggressively flags
  "autumn", "next week", "Fridays" as `DATE_TIME` (score 0.85). We did not plant
  `DATE_TIME`, so on clean text this raises the raw confidence stream above
  threshold. The adapter faithfully passes this through; whether `DATE_TIME` is
  "PII" is a policy choice, which is exactly the separation the architecture
  intends (the detector reports; ESP decides).

### Reproduce

```sh
# one-time: a Python 3.12 venv with real Presidio + spaCy model
/opt/homebrew/opt/python@3.12/bin/python3.12 -m venv eval/.venv
eval/.venv/bin/pip install presidio-analyzer presidio-anonymizer faker click typer
eval/.venv/bin/python -m spacy download en_core_web_lg

# generate the corpus with REAL Presidio output, then score the adapter
eval/.venv/bin/python eval/presidio_eval.py > eval/presidio_cases.jsonl
cargo run --example detector_eval
```

## Safety / jailbreak: Llama Guard / Lakera

We do **not** report a safety F1, by design rather than inability. A safety-detector
benchmark would measure *Llama Guard's / Lakera's* accuracy (the model vendor's),
not our code, exactly as the Presidio F1 above is mostly Presidio's. What we own
on the safety path is the same as on the DLP path: the adapter, the parser, and
fail-closed handling.

What *is* in place: the `LlamaGuardDetector` / `LakeraDetector` adapters and their
parsers (`parse_llama_guard`, `parse_lakera`) are validated against each tool's
documented native output format (unit tests in `src/afc.rs`).

Llama Guard *is* runnable locally (e.g. `ollama pull llama-guard3:8b` on Apple
Silicon; Ollama returns the exact `safe` / `unsafe\nS9` format our adapter
parses). The meaningful parity move with the Presidio side is therefore a **live
integration smoke test** (`RemoteCall → Ollama → LlamaGuardDetector → evidence`)
that proves the adapter handles a real model's output, *not* a scored accuracy
benchmark of someone else's model.

**Live smoke, done (2/2).** Run against Ollama `llama-guard3:1b`: a benign prompt
returned `safe` and a harmful prompt returned `unsafe\nS1`, and both were parsed
by the `LlamaGuardDetector` adapter into the expected evidence (2/2). This closes
the parity move: the adapter is confirmed on a real model's output. As above, no
safety F1 is claimed by design: accuracy is the vendor's, and a third-party
accuracy benchmark stays explicitly out of scope.
