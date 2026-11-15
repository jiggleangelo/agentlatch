# CRA readiness

This document describes readiness work, not compliance.

The MVP includes a local CycloneDX-shaped source SBOM generator, no third-party runtime dependencies, deny-by-default policy, a 300-second token TTL cap, bounded audit storage, admission auditing before connector execution, bounded unauthenticated audit events, atomic policy rate admission, bounded HTTP concurrency and request deadlines. It emits no request logs or telemetry.

The hosted CRA page displays a static summary. It does not scan the deployment root or publish its inventory. The local SBOM generator includes only project artifacts and skips symlinks.

Not claimed: product classification, conformity assessment, operational vulnerability intake/reporting, independently protected connector keys, external audit-head anchoring, durable storage, distributed denial-of-service resistance or a committed support period.

Contact collection is absent. The in-memory vault supplies only an application-level write-only interface; it is not a security boundary against process introspection.

Run python3 -m agentgate.release_check locally. Product release remains blocked until the required human evidence is present.
