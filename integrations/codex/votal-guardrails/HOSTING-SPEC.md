# Spec: host the approved Codex customer kit

## 1. Problem and outcome

Host the already prepared and user-approved 0.2.0 kit in integrations/codex/votal-guardrails. Customers can inspect the source, download a versioned archive, and follow GitHub installation instructions. Scope is packaging and documentation; no new product behavior is introduced.

## 2. Plane and latency contract

Neither the data-plane application nor the admin plane is modified. This repository addition is off hot path, no guarded-traffic impact. The opt-in customer adapter continues to call the existing data-plane input endpoint.

## 3. Data model

No new Redis keys, stored tenant configuration, or server state. Tenant scope remains derived from the customer-supplied runtime credential.

## 4. API and interface

No new HTTP API. The existing adapter uses POST /guardrails/input with X-API-Key. The existing local marketplace, launcher, and UserPromptSubmit hook are distributed together.

## 5. Security and backward compatibility

Installation is opt-in. No keys, local caches, author-machine paths, or unrelated checkout changes are published. Hook trust and customer acceptance tests remain required. Local checks can be disabled and do not constitute mandatory enterprise enforcement.

## 6. Packaging and deploy

One self-contained directory, versioned downloadable ZIP, checksums, installation guide, and tests. No new third-party dependencies, Dockerfile changes, or service image rebuilds. Use a feature branch and PR; preserve current repository runtime behavior.

## 7. Failure modes and edge cases

The existing adapter blocks rejected, ambiguous, redacted, and failed checks when it runs. Untrusted/disabled hooks, missing Python, process-launch failure, and host timeouts remain outside its blocking guarantee. Relocated paths with spaces are tested. Credentials are entered separately by each customer.

## 8. Test plan

Run the 18 supplied tests in a clean standard-library Python venv; verify source/archive inventories, portable paths, checksums, and no credential values. Complete repository CI before merge. Real tenant blocking and installed Codex activation remain customer acceptance tests; mocked tests do not establish them.
