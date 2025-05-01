#!/bin/bash
#
# Redeploys the pod-agent with a clean slate:
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
YAML_FILES=("network-policy.yaml" "pod-agent-daemonset.yaml")  # All YAML files in order

# ─── Build image → OCI tarball only (skips Docker's local image store) ─────────
echo "🛠️  (1/7) Building ${FULL_REF} to OCI tarball…"
docker buildx build \
  --progress=plain \
  --tag "${FULL_REF}" \
  --output "type=oci,dest=${TAR_FILE}" \
  .

# ─── Remove *all* dangling data from Docker (no layers kept) ───────────────────
echo "🧹 (2/7) Docker: pruning unused objects…"
docker system prune -af --volumes

# ─── Import the tarball into containerd & drop the tar ─────────────────────────
echo "💾 (3/7) Importing image into k3s containerd..."
sudo k3s ctr --namespace k8s.io images import "${TAR_FILE}"
if [ $? -ne 0 ]; then
    echo "❌ Image import failed!"
fi
rm -f "${TAR_FILE}"

# ─── Prune unused / old images in containerd (keeps ones in use) ───────────────
echo "🧹 (4/7) containerd: pruning unused images..."
# sudo k3s crictl rmi --prune # <<< Commented out - seems too aggressive

# ─── Delete existing resources ─────────────────────────────────────────────────
echo "🗑️  (5/7) Removing existing resources..."
kubectl delete networkpolicy rasp-network-policy --ignore-not-found
kubectl delete pod -l "app=${IMAGE_NAME}" --force --grace-period=0 --ignore-not-found

# ─── Apply all YAML files in order ────────────────────────────────────────────
echo "🚀 (6/7) Applying Kubernetes resources..."
for yaml in "${YAML_FILES[@]}"; do
    if [ -f "$yaml" ]; then
        echo "📄 Applying $yaml..."
        kubectl apply -f "$yaml"
    else
        echo "⚠️  Warning: $yaml not found"
    fi
done

# ─── Wait for pods to be ready ────────────────────────────────────────────────
echo "⏳ (7/7) Waiting for pods to be ready..."
kubectl wait --for=condition=ready pod -l "app=${IMAGE_NAME}" --timeout=60s

echo "✅ Deployment complete!"