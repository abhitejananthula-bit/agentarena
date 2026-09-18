# Sample Mock Data & Ground Truth Reference Answers

This folder contains a clean tabular export of the mock cybersecurity environment world state and development tasks **with all corresponding ground truth answers**.

---

## Files Included

1. **`tasks.csv`**
   - Inbound email / message inquiries evaluated by the mock simulator.
   - Columns:
     - `task_id`: Unique identifier of the task (e.g. `TASK-DEV-001`).
     - `customer_id`: Target employee recipient ID (`EMP-...`).
     - `customer_message`: Formatted inbound message with RFC headers.
     - `input_payload`: JSON dictionary containing structured `message_id`, `thread_id`, `sender_email`, `subject`, and `message_body`.

2. **`ground_truth.csv`**
   - Corresponding ground truth triage determinations matching `task_id`.
   - Columns:
     - `task_id`: Matches task identifier from `tasks.csv`.
     - `expected_resolution`: Ground truth triage resolution (`allow`, `warn`, `quarantine`, `escalate`).
     - `must_escalate`: Whether Tier 2 SOC escalation is required (`True` / `False`).
     - `required_evidence`: JSON array of required evidence IDs that must be cited (`EMP-*`, `DOM-*`, `MSG-*`, `THR-*`, `POL-*`).
     - `category`: Attack categorization (`phishing`, `impersonation`, `credential_harvesting`, `prompt_injection`, `legitimate`).
     - `issue`: Specific classified incident issue.
     - `severity`: Assessed incident severity (`low`, `medium`, `high`, `critical`).
     - `expected_action_tool`: Server-enforced action tool corresponding to the resolution.

3. **`directory.csv`**
   - Corporate employee directory records.
   - Columns: `id`, `full_name`, `official_email`, `department`, `job_title`, `role_level`, `manager_email`, `employment_status`, `mfa_enabled`.
   - Access at runtime via: `tools.lookup_directory(identifier)`.

4. **`domains.csv`**
   - Official institution and trusted partner domains.
   - Columns: `domain_id`, `domain_name`, `domain_type`, `reputation`, `threat_score`.
   - Access at runtime via: `tools.get_approved_domains()`.

5. **`threat_intel.csv`**
   - Real-time threat intelligence reputation feed for suspicious or known malicious domains.
   - Columns: `domain_id`, `domain`, `reputation`, `threat_score`, `category`, `known_lookalike_target`, `first_seen`.
   - Access at runtime via: `tools.inspect_domain_reputation(domain)`.

6. **`security_policies.csv`**
   - Institutional cybersecurity compliance rules, wire transfer limits, and triage policies.
   - Columns: `id`, `title`, `category`, `policy_rules`, `enforcement_action`.

7. **`historical_threats.csv`**
   - Historical security incident logs, previous attacks, and multi-turn message thread traces.
   - Columns: `thread_id`, `message_id`, `sender_email`, `subject`, `timestamp`, `triage_status`.
   - Access at runtime via: `tools.get_thread_history(thread_id)`.
