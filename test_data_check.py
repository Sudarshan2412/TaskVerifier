import json
import sys

# Load and check the subset
with open("cybergym_subset.json") as f:
    subset = json.load(f)

print(f"✓ Loaded {len(subset)} CVEs from cybergym_subset.json")
print(f"✓ Sample CVE: {subset[0]['cve_id']}")
print(f"✓ Available fields: {list(subset[0].keys())}")

# Check which bucket field exists
bucket_fields = ["poc_length_bucket", "bucket", "poc_bucket", "length_bucket"]
found = None
for field in bucket_fields:
    if field in subset[0]:
        found = field
        break

if found:
    print(f"✓ Found bucket field: {found}")
else:
    print(f"✗ No bucket field found. Will use index-based selection.")

# Test the normalization function
sys.path.insert(0, '.')
import json

def _normalize_cve_entry(cve: dict) -> dict:
    normalized = {}
    normalized["id"] = cve.get("cve_id", "UNKNOWN")
    normalized["vuln_class"] = cve.get("vuln_class", "other")
    normalized["sanitizer_type"] = cve.get("sanitizer_type", "unknown")
    normalized["crash_description"] = cve.get("crash_description", "")
    normalized["poc_bucket"] = cve.get("poc_bucket") or cve.get("poc_length_bucket", "unknown")
    normalized["target_source"] = cve.get("target_source", "// Placeholder source code")
    return normalized

normalized = _normalize_cve_entry(subset[0])
print(f"\n✓ Normalized entry fields: {list(normalized.keys())}")
print(f"  id: {normalized['id']}")
print(f"  vuln_class: {normalized['vuln_class']}")
print(f"  poc_bucket: {normalized['poc_bucket']}")
