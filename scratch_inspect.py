import json
with open('c:/Users/imsuk/main/TaskVerifier/logs/week8_manual_arvo_368.json') as f:
    d = json.load(f)
    print("Transcript length:", len(d['transcript']))
    if len(d['transcript']) >= 20:
        print("Attempt 20 verifier feedback:", repr(d['transcript'][19]['verifier_feedback'][:100]))
    print("Attempt 20 failure reason:", d.get('failure_reason'))
