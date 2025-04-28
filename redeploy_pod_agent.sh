#!/usr/bin/env bash
#
# Safe redeploy script for the pod-agent DaemonSet on a k3s node
# ──────────────────────────────────────────────────────────────
# • Builds the image straight into an OCI tarball (no layers left in /var/lib/docker)
# • Imports that tarball into k3s’ containerd
# • Prunes old images/layers in both Docker and containerd
# • Restarts the DaemonSet cleanly
# • Leaves root disk clean and predictable
#
# Requirements: Docker Buildx (Docker ≥ 20.10), k3s with ctr/crictl on PATH
#               Run as a user that can sudo (for ctr/crictl).
set -euo pipefail
IFS=$'\n\t'

# ─── Configuration ──────────────────────────────────────────────────────────────
IMAGE_NAME="pod-agent"
IMAGE_TAG="latest"                     # change to a version if you want history
FULL_REF="docker.io/library/${IMAGE_NAME}:${IMAGE_TAG}"
TAR_FILE="${IMAGE_NAME}.oci.tar"       # lives only for a few seconds
DAEMONSET_YAML="pod-agent-daemonset.yaml"

# ─── Build image → OCI tarball only (skips Docker's local image store) ─────────
echo "🛠️  (1/6) Building ${FULL_REF} to OCI tarball…"
docker buildx build \
  --progress=plain \
  --tag "${FULL_REF}" \
  --output "type=oci,dest=${TAR_FILE}" \
  .

# ─── Remove *all* dangling data from Docker (no layers kept) ───────────────────
echo "🧹 (2/6) Docker: pruning unused objects…"
docker system prune -af --volumes

# ─── Import the tarball into containerd & drop the tar ─────────────────────────
echo "📦 (3/6) Importing image into k3s containerd…"
sudo k3s ctr images import "${TAR_FILE}"
rm -f "${TAR_FILE}"

# ─── Prune unused / old images in containerd (keeps ones in use) ───────────────
echo "🧹 (4/6) containerd: pruning unused images…"
sudo k3s crictl rmi --prune

# ─── Restart the DaemonSet (delete pods; controller recreates) ─────────────────
echo "🔄 (5/6) Forcing pod refresh…"
kubectl delete pod -l "app=${IMAGE_NAME}" --force --grace-period=0 --ignore-not-found

echo "🚀 (6/6) Applying ${DAEMONSET_YAML}…"
kubectl apply -f "${DAEMONSET_YAML}"

echo "✅ Done!   Follow rollout with:  kubectl get pods -l app=${IMAGE_NAME} -w"