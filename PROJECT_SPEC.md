# PROJECT SPEC — AI Security Shield

## 1. What is this?

AI Security Shield is a prototype security layer that analyzes untrusted external content for potentially malicious instructions that could manipulate an AI agent through indirect prompt injection.

The prototype focuses on one flow: detecting suspicious instructions, explaining the associated risk, and helping the user decide whether to allow, isolate, or block the content.

---

## 2. Who uses it?

The primary user is a developer or security practitioner who builds or operates AI agents that process untrusted external content such as webpages, documents, emails, or tool-generated content.

The prototype is intended for users who need to inspect external content before allowing an AI agent to act on it.

---

## 3. What must it do?

The prototype must:

1. Accept user-provided external/untrusted content.
2. Analyze the content for potential indirect prompt-injection patterns.
3. Identify suspicious instructions or patterns.
4. Assign a risk level.
5. Explain in simple language why the content was flagged.
6. Show the suspicious portion of the content where possible.
7. Give the user a clear decision such as Allow, Isolate/Review, or Block.
8. Handle legitimate content without automatically treating it as malicious.
9. Provide a clear result that a first-time user can understand.

---

## 4. What does it NOT do?

The prototype will NOT:

- Guarantee detection of every prompt-injection attack.
- Act as a complete enterprise cybersecurity platform.
- Replace existing endpoint, network, email, or application security systems.
- Automatically execute actions on behalf of an AI agent.
- Provide a complete autonomous AI-agent platform.
- Claim that all external content is malicious.
- Store sensitive user information unnecessarily.
- Claim that existing prompt-injection defenses are ineffective.
- Cover every possible type of AI security threat.

---

## 5. What data does it use?

The prototype uses:

- User-provided text or external-content samples.
- Controlled benign test examples.
- Controlled malicious/prompt-injection test examples.
- Detection results and explanations.

The initial prototype should avoid collecting unnecessary personal or confidential information.

Test data should be controlled and safe to use.

---

## 6. What are the constraints?

The project is a hackathon prototype and therefore has:

- Limited development time.
- Limited testing data.
- Limited computing/API resources.
- Prototype-level rather than production-level security.
- A requirement to demonstrate one clear working flow.
- A requirement to explain and test AI-generated output.
- A requirement to keep API keys and credentials outside the submitted source code.

The system should prioritize clarity, testability, and stability over a large number of features.

---

## 7. What does DONE mean?

The prototype is considered complete when:

1. A user can submit external content.
2. The system analyzes the content.
3. The system produces a risk assessment.
4. Suspicious instructions are highlighted or identified.
5. The system provides a human-readable explanation.
6. The user receives a clear action choice.
7. Benign and malicious test cases can be demonstrated.
8. Empty, very long, and unsupported inputs have been tested.
9. The main flow works reliably enough for a demonstration.
10. A new user can understand the result without requiring our verbal explanation.

---

## 8. What is still unknown?

The following remain open questions:

- How accurately can the prototype detect indirect prompt injection?
- What is the false-positive rate on legitimate content?
- What is the false-negative rate on malicious content?
- Which attack patterns are hardest to detect?
- How well does the explanation help users understand the risk?
- What security gap remains after considering existing defenses?
- Whether the target users would actually use a separate detection layer.
- Which deployment environment would be appropriate for a production version.

These questions should be treated as hypotheses until supported by testing or user evidence.

---

# CORE FLOW

## Input → Detect → Explain → Decide

### Input
User submits external/untrusted content.

### Detect
The system analyzes the content for potential indirect prompt injection.

### Explain
The system identifies suspicious instructions, assigns a risk level, and explains the reason.

### Decide
The user chooses whether to allow, isolate/review, or block the content.

---

# SUCCESS CRITERIA

The prototype should demonstrate that:

- The main flow works from beginning to end.
- Known malicious test cases can be identified.
- Legitimate examples are not automatically flagged as malicious.
- Results are understandable to a first-time user.
- The system handles unexpected inputs without crashing.
- The implementation remains within the defined scope.

# TECH STACK

## Frontend
HTML, CSS, and JavaScript.

Reason:
The team already has experience with these technologies, allowing rapid development and easier debugging within the hackathon constraints.

## Backend
Python with Flask.

Reason:
The team has existing Python and Flask experience, and Flask is sufficient for exposing the prototype's analysis endpoint without introducing unnecessary backend complexity.

## Detection
A hybrid detection approach using rule-based checks and an LLM/API.

Reason:
Rule-based checks can identify known suspicious patterns quickly, while an AI model can analyze context and explain why content may be risky. Combining both reduces dependence on a single detection method.

## Data and Storage
Local JSON/CSV test datasets and SQLite where persistent storage is required.

Reason:
The prototype needs controlled benign and malicious examples for testing without requiring a complex database infrastructure.

## Version Control
Git and GitHub.

Reason:
The five-member team needs a shared codebase and version history.

## Hosting
Local development first, followed by simple cloud deployment if required for the final demonstration.

Reason:
The prototype should be tested locally before deployment so that hosting does not become a source of unnecessary complexity.

## Security Constraints
API keys and credentials must never be stored in source code or committed to GitHub. They must be provided through environment variables.
