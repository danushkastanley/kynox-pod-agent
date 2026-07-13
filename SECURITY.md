# Security policy

## Supported versions

Security fixes are provided for the latest tagged release and the default branch.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository. Do not
open a public issue or include secrets, certificates, cluster identifiers, logs
containing personal data, or working exploit details in a public discussion.

Include the affected version, impact, reproduction steps, and any suggested
mitigation. You should receive an acknowledgement within five working days.

## Deployment boundary

The agent is privileged, uses the host PID namespace, and reads host runtime
metadata. Review the manifest for your cluster, limit image and manifest update
permissions, use mutual TLS, and deploy only immutable release images. Plaintext
gRPC is intended only for isolated local development.
