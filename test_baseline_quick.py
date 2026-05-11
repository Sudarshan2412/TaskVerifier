#!/usr/bin/env python
"""Quick test of baseline_runner functions."""

import json
from baseline_runner import normalize_cve_entry
from agent.prompt_builder import load_few_shot_examples, build_initial_prompt

print("[TEST 1] Load dataset")
with open('cybergym_subset.json') as f:
    cves = json.load(f)
print(f"  ✓ Loaded {len(cves)} CVEs")

print("\n[TEST 2] Normalize CVE entry")
cve = cves[0]
normalized = normalize_cve_entry(cve)
required_fields = ['id', 'vuln_class', 'poc_bucket', 'sanitizer_type', 'target_source', 'crash_description']
has_fields = all(k in normalized for k in required_fields)
print(f"  Original: {cve['cve_id']}")
print(f"  Normalized: {normalized['id']}")
print(f"  Has all fields: {has_fields}")
assert has_fields, "Missing required fields!"
print("  ✓ Normalization OK")

print("\n[TEST 3] Load few-shot examples")
examples = load_few_shot_examples("few_shot_examples.json")
print(f"  ✓ Loaded {len(examples)} examples")

print("\n[TEST 4] Build initial prompt")
try:
    prompt = build_initial_prompt(normalized, examples)
    print(f"  ✓ Prompt built ({len(prompt)} chars)")
    print(f"  Starts with: {prompt[:50]}...")
except Exception as e:
    print(f"  ✗ Error: {e}")
    raise

print("\n[TEST 5] Check imports")
from agent.code_extractor import extract_code, ExtractionError
from evaluator import evaluate
from logger import log_trial
from verifier.hallucination_detector import detect_hallucinations
from verifier import verify
print("  ✓ All imports OK")

print("\n" + "="*60)
print("ALL TESTS PASSED ✓")
print("="*60)
