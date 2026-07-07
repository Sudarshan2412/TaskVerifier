You are acting as a senior software architect, benchmark auditor, and autonomous-agent researcher.

I am attaching the latest TaskVerifier run artifacts (report(s), transcript(s), and any supporting files).

Your task is to independently analyze these artifacts and produce a detailed implementation plan for improving the framework.

Do NOT execute any changes.
Do NOT generate code.
Do NOT modify any files.

Your job is to reason about the framework first and produce a high-quality implementation strategy.

====================================================
OBJECTIVE
====================================================

The objective is NOT to improve performance on this specific benchmark.

The objective is to improve the verifier framework itself while preserving benchmark integrity.

The framework must remain reusable across many repositories, parsers, file formats, and vulnerability classes.

====================================================
STEP 1 — ANALYZE THE ATTACHED ARTIFACTS
====================================================

Carefully read every attached report and transcript yourself.

Do not rely on assumptions from previous conversations.

From the evidence alone determine:

- why the latest run failed
- which framework improvements appear to be working
- which previous improvements are still insufficient
- where the framework is making incorrect assumptions
- where the retry loop is reinforcing incorrect reasoning
- whether verifier feedback is actually helping or accidentally misleading the agent
- whether prompt construction is introducing unnecessary bias
- whether any reusable abstractions are still missing

Only identify issues supported by evidence from the attached logs.

====================================================
STEP 2 — INFORMATION FLOW AUDIT
====================================================

Audit every piece of information that reaches the agent.

Determine whether any information would realistically be unavailable to a human vulnerability researcher before discovering the vulnerability.

Classify all findings as:

- Safe
- Safe Format Knowledge
- General Parser Knowledge
- Vulnerability Knowledge
- Ground-Truth Leakage

Treat general format knowledge (file grammar, encoding rules, parser-independent specifications, etc.) as acceptable.

Treat anything that reveals:

- vulnerable execution paths
- trigger conditions
- expected crash behaviour
- solution-derived reasoning
- verifier guidance that progressively narrows the search space

as potential leakage.

Only report genuine leakage.

If you conclude the framework is currently leakage-free, explain why.

====================================================
STEP 3 — GENERALIZATION AUDIT
====================================================

Every proposed improvement must satisfy ALL of the following:

- Would this still improve the framework if the current benchmark disappeared tomorrow?
- Would it benefit multiple repositories?
- Would it benefit multiple parsers?
- Would it benefit multiple file formats?
- Would it benefit multiple vulnerability classes?

Reject any recommendation that fails these tests.

Hardcoding is not allowed.

Specifically avoid:

- hardcoded CVE IDs
- hardcoded repository names
- hardcoded parser names
- hardcoded vulnerable functions
- hardcoded operators
- hardcoded offsets
- benchmark-specific prompt logic
- benchmark-specific retry logic
- benchmark-specific verifier behaviour
- one-off heuristics
- special-case branches

If a recommendation depends on recognizing a specific benchmark, redesign it.

====================================================
STEP 4 — FRAMEWORK DESIGN REVIEW
====================================================

Identify the remaining architectural weaknesses.

Think beyond the current benchmark.

Consider:

- abstraction boundaries
- extensibility
- maintainability
- information flow
- retry strategy
- verifier architecture
- prompt architecture
- context management
- scalability
- future benchmark support

Determine which improvements provide the highest long-term value.

====================================================
STEP 5 — IMPLEMENTATION PLAN
====================================================

Do NOT write code.

Instead produce a prioritized implementation plan.

For each proposed improvement include:

- Title
- Problem it solves
- Evidence from the attached logs
- Why it generalizes
- Why it is leakage-free
- Expected impact
- Complexity (Low / Medium / High)
- Dependencies
- Risks
- Suggested implementation order

If a recommendation would require touching multiple components, explain how they interact.

====================================================
OUTPUT
====================================================

Structure your response as:

1. Executive Summary
2. Root Cause Analysis
3. Leakage Audit
4. Generalization Audit
5. Architectural Weaknesses
6. Prioritized Implementation Plan

Keep the discussion focused on framework improvements.

Do not generate code.

Do not generate patches.

Do not modify files.

The goal of this review is to produce the best possible implementation strategy before any code is written.