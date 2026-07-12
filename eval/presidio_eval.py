#!/usr/bin/env python3
"""Live Presidio DLP benchmark. Generates a labeled, seeded synthetic dataset,
runs the REAL Microsoft Presidio analyzer over it, and emits one JSONL line per
case containing Presidio's *native* output plus ground-truth labels.

The native JSON is consumed unchanged by our Rust `PresidioDetector` adapter
(`src/afc.rs::parse_presidio`) in `examples/detector_eval.rs`, so the metrics we
report measure the real detector AND our real adapter end to end. Nothing is
mocked or hand-tuned.

Dataset is synthetic/templated with Faker (seeded => reproducible), the standard
approach for PII eval (cf. microsoft/presidio-research). Ground-truth entity
types use Presidio's own vocabulary so the comparison is apples-to-apples.

Usage:  eval/.venv/bin/python eval/presidio_eval.py > eval/presidio_cases.jsonl
"""
import json
import random
import sys

from faker import Faker
from presidio_analyzer import AnalyzerEngine

SEED = 42
PER_TYPE = 40       # positive samples per entity type
NEGATIVES = 100     # samples containing no PII

fake = Faker("en_US")
Faker.seed(SEED)
random.seed(SEED)

# (Presidio entity type, generator): types Presidio supports out of the box.
GENERATORS = {
    "PERSON": lambda: fake.name(),
    "EMAIL_ADDRESS": lambda: fake.email(),
    "PHONE_NUMBER": lambda: fake.phone_number(),
    "CREDIT_CARD": lambda: fake.credit_card_number(),
    "US_SSN": lambda: fake.ssn(),
    "IP_ADDRESS": lambda: fake.ipv4(),
    "LOCATION": lambda: fake.city(),
    "URL": lambda: fake.url(),
    "IBAN_CODE": lambda: fake.iban(),
}

TEMPLATES = [
    "Please contact {v} as soon as possible.",
    "The record on file lists {v} for this account.",
    "We updated the customer profile with {v} yesterday.",
    "Forward the report to {v} when it is ready.",
    "Our notes show {v} from the previous session.",
    "Reference value: {v} (do not share externally).",
]

NEGATIVE_SENTENCES = [
    "The quarterly review meeting is scheduled for next week.",
    "Our team shipped the new caching layer ahead of schedule.",
    "Please remember to water the office plants on Fridays.",
    "The build pipeline now runs unit tests in parallel.",
    "We discussed the roadmap and agreed on three priorities.",
    "The weather has been unusually mild this autumn.",
    "Documentation for the API was refreshed last sprint.",
    "Coffee supplies in the kitchen are running low again.",
]


def build_dataset():
    cases = []
    for etype, gen in GENERATORS.items():
        for _ in range(PER_TYPE):
            tmpl = random.choice(TEMPLATES)
            text = tmpl.format(v=gen())
            cases.append((text, [etype]))
    for _ in range(NEGATIVES):
        text = random.choice(NEGATIVE_SENTENCES)
        cases.append((text, []))
    random.shuffle(cases)
    return cases


def main():
    analyzer = AnalyzerEngine()
    cases = build_dataset()
    print(f"# {len(cases)} cases, Presidio {', '.join(sorted(GENERATORS))}",
          file=sys.stderr)
    for text, gt_types in cases:
        results = analyzer.analyze(text=text, language="en")
        native = [
            {"entity_type": r.entity_type, "start": r.start,
             "end": r.end, "score": round(float(r.score), 4)}
            for r in results
        ]
        print(json.dumps({
            "text": text,
            "gt_types": gt_types,
            "presidio_raw": json.dumps(native),
        }))


if __name__ == "__main__":
    main()
