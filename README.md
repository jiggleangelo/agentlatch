# agentlatch

Prototype: Dry-run AI agent tool calls against your policy: agentlatch

**Use it free, no account:** https://app-agentlatch.manykiln.com/  
**Try the demo (made-up data):** https://try-agentlatch.manykiln.com/  
**Product page:** https://agentlatch.manykiln.com/

> Built and maintained by AI agents at [Manykiln](https://manykiln.com), a studio whose products are written, tested and operated by AI agents. This is a working prototype, not a finished product. No payment is taken anywhere: any checkout, waitlist or payment code in this project runs against fakes only, and the hosted demo uses made-up data.

- Status: prototype; run the 39 automated tests yourself with `python3 -m unittest discover`
- Runs on the Python 3.12 standard library; run the usable app with `python3 app.py` (see below)
- Licence: MIT. Free to use, fork and improve.
- Issues and pull requests are not monitored yet.

---

# AgentGate MVP and agentlatch

The original `demo.py` is a made-up-data demonstration of agent credentials, tokens, policy evaluation, fake connectors and audit tampering. It is not a production gateway. Its original modules and tests remain unchanged.

## Usable app

`agentlatch` in `app.py` is a persistent, self-serve policy checker using Python 3.12 and the standard library only. It never invokes tools, issues credentials, charges money or calls an AI model. Agents are plain policy subject names. Evaluation reuses the original deterministic PolicyEngine through a hosted subclass that supplies exact constraint reason codes for every argument name.

Start one process:

```sh
export DATA_DIR=/absolute/path/to/persistent-data
export PUBLIC_BASE_URL=https://app-agentlatch.manykiln.com
export APP_HTTPS_TERMINATED=true
export APP_HOST=127.0.0.1
export PORT=8080
python3 app.py
```

For direct local use, omit PUBLIC_BASE_URL and open the exact printed bind host and port, normally `http://127.0.0.1:8080`. Host and same-origin POST checks remain enabled locally. Non-loopback binding requires both an HTTPS PUBLIC_BASE_URL and APP_HTTPS_TERMINATED=true. PUBLIC_BASE_URL must contain only an HTTPS origin. GET /healthz returns ok with the configured Host header.

Use only one process per DATA_DIR. Thread-safe transactions serialize each workspace operation and atomically replace a complete state.json snapshot. They charge one write per successful operation, not per internal log entry. Old workspaces using separate JSON files are read and migrated on their next successful write. Transactions reject capacity or rate failures without saving partial policy, suite or log changes. Fixed lock stripes cannot evict an active workspace lock.

A workspace link is its only access key. Bookmark it; raw tokens are not stored and cannot be recovered. Separate read-only review links can be revoked. All workspace and review responses use no-store and noindex headers; review HTML also includes a noindex meta tag.

## Inputs and results

Import AgentGate v1 policies up to 32 KB and 200 rules. Import MCP tools/list responses, bare arrays, or one tool name per line, up to 1 MB, 200 tools and 64 properties per tool. Legacy oversized catalogues can be exported and replaced; the tool page displays at most 200 entries and never constructs an agents-times-tools list.

Starter generation accepts up to 100 agent names and 200 explicitly selected agent|tool pairs. Empty selection generates no allow rules. Rule count is checked before expansion and encoded size is checked while building the policy. Constraints derive from maximum, minimum, enum and maxLength. Unbounded strings receive max_len 256 and a TODO finding.

Policy validation displays the engine's error path while preserving the submitted editor text. Ordinary structural names and catalogue descriptions do not undergo entropy guessing; known credential patterns are still rejected. Constraint values and call arguments retain secret detection. Secret-named argument fields, including nested password and api_key fields, are withheld before persistence.

Single calls show allow or deny, exact reason and rule index. Save as test case adds the call to the saved suite. Saved ordinary arguments remain plaintext so they can be rerun. Do not enter real API keys, passwords, tokens or other people's personal data.

Suites accept up to 500 cases. Run saved suite preserves existing cases. Replace and run explicitly replaces them, including with an empty suite. Invalid JSONL displays line numbers and preserves the previous suite. Partial reports carry a persisted evaluator checkpoint containing simulated time and rate history. Continue resumes from that checkpoint, verifies its policy/suite fingerprint and logs only newly evaluated cases. Compatibility offset replay is also deadline bounded.

Policy saves and restores rerun the suite and show outcome differences. The policy page offers view and restore controls for the last 20 stored versions. Lint uses indexed tool and deny lookups rather than scanning every rule for every catalogue tool.

## Decision log

Every single-call result and every newly evaluated suite case is appended to the keyed hash chain. Suite events are committed together, so a suite with 500 failing expectations still produces its report without consuming 500 write allowances.

The log has a deliberate 2,000-entry capacity. Overview and Log show usage and archive instructions. An operation needing more entries is refused with an explicit archive message, and its transaction saves no changes. Entries are never silently trimmed or renumbered. Log provides Previous/Next pagination, Verify, and Download and clear log. Keep the downloaded archive: clearing starts a fresh chain whose HMAC-covered genesis reason contains the previous head hash.

Workspace exports and log archives include verification keys. Anyone holding those keys could also rewrite the chain. This is tamper evidence, not independent external anchoring. Archive downloads are not externally backed up by the app.

## Deployment privacy and client limits

Workspace and share tokens appear in URL paths. Disable request URL logging at every reverse proxy, ingress, CDN and load balancer, including error logs, tracing and request capture. App logging is disabled, but the app cannot configure or verify upstream logging. The supplied deploy/nginx.conf disables Nginx access and error logging for this virtual host. Apply equivalent settings to every upstream layer before accepting real users.

Creation limits use the TCP peer address: 60 workspaces per client per hour. Untrusted Forwarded, X-Forwarded-For and X-Real-IP headers are ignored. A conventional reverse proxy would make all visitors share its address. The example therefore uses Nginx transparent upstream source binding. This requires appropriate OS capabilities and return-path routing; configure and test that routing in your deployment. Alternatively use a network ingress that preserves client source addresses. Do not deploy behind a source-collapsing proxy and assume the application can identify clients from headers. The example is configuration guidance, not an applied or verified deployment.

Resource limits include 1 MB request bodies, 500 suite cases, 5 MB per workspace, 3,000 workspaces, 30 successful writes per workspace per minute, 10 suite runs per minute, bounded worker threads, socket timeouts and suite deadlines. APP_DATA_CAP_MB defaults to 200. Creation source buckets are bounded and expire after an hour. There are no outbound network calls, analytics, third-party assets or contact fields.

Unused workspaces expire after 24 hours; inactive workspaces expire after 90 days. Cleanup runs at startup and daily. Deletion writes a tombstone, and cleanup uses the same workspace locks as requests.

## Validation

```sh
python3 -m unittest discover -s tests
python3 -m agentgate.sbom
python3 -m agentgate.release_check
```

Tests in tests/test_review_fixes.py cover catalogue and generation bounds, indexed lint, exact reasons, batched audit writes, full-log rollback and archive recovery, saved-suite reruns, validation forms, secret withholding, structural-name false positives, per-source creation limits, local and hosted origin enforcement, concurrent saves, stable locks, continuation checkpoints, review noindex, log pagination, version restoration and deployment logging configuration.

## CRA and release status

Readiness, not compliance. Classification, conformity assessment, vulnerability reporting, support commitments, export review, release-key custody, partner terms and privacy review require human evidence. The original release check remains blocked until the required signed evidence exists.
