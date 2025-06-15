#!/bin/bash
#
# Redeploys the pod-agent with enhanced cluster-wide monitoring:
# • Builds and imports the enhanced monitoring image
# • Deploys to security-monitoring namespace with cluster-wide coverage
# • Sets up proper RBAC and tolerations for control plane monitoring
# • Configures comprehensive host and container monitoring
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
NAMESPACE="security-monitoring"         # Enhanced namespace for cluster monitoring
APP_LABEL="pod-agent-enhanced"         # Enhanced app label

# YAML files for enhanced cluster monitoring (applied in order)
YAML_FILES=(
    "enhanced-daemonset.yaml"          # Main enhanced DaemonSet with cluster-wide monitoring
    "network-policy.yaml"              # Network policies (if exists)
)

# Legacy cleanup files (for migration from old deployment)
LEGACY_YAML_FILES=(
    "pod-agent-daemonset.yaml"         # Old DaemonSet configuration
)

echo "🔍 Enhanced Pod Agent Cluster-Wide Monitoring Deployment"
echo "==========================================================="
echo "Namespace: ${NAMESPACE}"
echo "App Label: ${APP_LABEL}"
echo "Image: ${FULL_REF}"
echo ""

# ─── Build image → OCI tarball only (skips Docker's local image store) ─────────
echo "🛠️  (1/9) Building enhanced ${FULL_REF} to OCI tarball…"
docker buildx build \
  --progress=plain \
  --tag "${FULL_REF}" \
  --output "type=oci,dest=${TAR_FILE}" \
  .

# ─── Remove *all* dangling data from Docker (no layers kept) ───────────────────
echo "🧹 (2/9) Docker: pruning unused objects…"
docker system prune -af --volumes

# ─── Import the tarball into containerd & drop the tar ─────────────────────────
echo "💾 (3/9) Importing enhanced image into k3s containerd..."
sudo k3s ctr --namespace k8s.io images import "${TAR_FILE}"
if [ $? -ne 0 ]; then
    echo "❌ Enhanced image import failed!"
    exit 1
fi
rm -f "${TAR_FILE}"

# ─── Prune unused / old images in containerd (keeps ones in use) ───────────────
echo "🧹 (4/9) containerd: pruning unused images..."
# sudo k3s crictl rmi --prune # <<< Commented out - seems too aggressive

# ─── Clean up legacy deployment (if exists) ───────────────────────────────────
echo "🗑️  (5/9) Cleaning up legacy pod-agent deployment..."
echo "   Removing legacy resources..."

# Remove legacy DaemonSet and resources
kubectl delete daemonset pod-agent --ignore-not-found --timeout=30s
kubectl delete networkpolicy rasp-network-policy --ignore-not-found

# Force remove any stuck legacy pods
kubectl delete pod -l "app=pod-agent" --force --grace-period=0 --ignore-not-found

# Clean up legacy RBAC if it exists
kubectl delete clusterrolebinding pod-agent --ignore-not-found
kubectl delete clusterrole pod-agent --ignore-not-found
kubectl delete serviceaccount pod-agent --ignore-not-found

echo "   Legacy cleanup complete."

# ─── Clean up existing enhanced deployment ─────────────────────────────────────
echo "🗑️  (6/9) Cleaning up existing enhanced deployment..."

# Remove enhanced resources in the security-monitoring namespace
kubectl delete daemonset ${APP_LABEL} -n ${NAMESPACE} --ignore-not-found --timeout=30s
kubectl delete pod -l "app=${APP_LABEL}" -n ${NAMESPACE} --force --grace-period=0 --ignore-not-found

# Clean up enhanced RBAC
kubectl delete clusterrolebinding ${APP_LABEL} --ignore-not-found
kubectl delete clusterrole ${APP_LABEL} --ignore-not-found
kubectl delete serviceaccount ${APP_LABEL} -n ${NAMESPACE} --ignore-not-found

# Note: We don't delete the namespace as it might contain other resources
echo "   Enhanced deployment cleanup complete."

# ─── Verify cluster requirements ──────────────────────────────────────────────
echo "🔍 (7/9) Verifying cluster requirements for enhanced monitoring..."

# Check if we have control plane nodes
CONTROL_PLANE_NODES=$(kubectl get nodes -l node-role.kubernetes.io/control-plane --no-headers 2>/dev/null | wc -l || echo "0")
MASTER_NODES=$(kubectl get nodes -l node-role.kubernetes.io/master --no-headers 2>/dev/null | wc -l || echo "0")
TOTAL_CONTROL_NODES=$((CONTROL_PLANE_NODES + MASTER_NODES))

echo "   Control plane nodes detected: ${TOTAL_CONTROL_NODES}"
echo "   Worker nodes: $(kubectl get nodes --no-headers | wc -l)"

if [ ${TOTAL_CONTROL_NODES} -gt 0 ]; then
    echo "   ✅ Control plane monitoring will be enabled"
else
    echo "   ⚠️  No control plane nodes detected - cluster monitoring will be worker-only"
fi

# ─── Apply enhanced YAML files in order ───────────────────────────────────────
echo "🚀 (8/9) Applying enhanced Kubernetes resources..."

# Ensure namespace exists first
echo "📁 Creating namespace: ${NAMESPACE}"
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

for yaml in "${YAML_FILES[@]}"; do
    if [ -f "$yaml" ]; then
        echo "📄 Applying enhanced configuration: $yaml..."
        kubectl apply -f "$yaml"
        
        # Add a brief pause between applications to ensure proper ordering
        sleep 2
    else
        echo "⚠️  Warning: Enhanced configuration $yaml not found"
        echo "   Available files:"
        ls -la *.yaml 2>/dev/null || echo "   No YAML files found"
    fi
done

# ─── Wait for enhanced pods to be ready ───────────────────────────────────────
echo "⏳ (9/9) Waiting for enhanced monitoring pods to be ready..."
echo "   Monitoring deployment in namespace: ${NAMESPACE}"

# Wait with more detailed feedback
TIMEOUT=120  # Increased timeout for cluster-wide deployment
WAIT_SECONDS=0

while [ ${WAIT_SECONDS} -lt ${TIMEOUT} ]; do
    READY_PODS=$(kubectl get pods -n ${NAMESPACE} -l "app=${APP_LABEL}" --no-headers 2>/dev/null | grep -c "Running" || echo "0")
    TOTAL_PODS=$(kubectl get pods -n ${NAMESPACE} -l "app=${APP_LABEL}" --no-headers 2>/dev/null | wc -l || echo "0")
    
    if [ ${TOTAL_PODS} -gt 0 ] && [ ${READY_PODS} -eq ${TOTAL_PODS} ]; then
        echo "   ✅ All ${TOTAL_PODS} enhanced monitoring pods are ready!"
        break
    fi
    
    echo "   ⏳ Enhanced monitoring pods status: ${READY_PODS}/${TOTAL_PODS} ready (${WAIT_SECONDS}s elapsed)"
    sleep 5
    WAIT_SECONDS=$((WAIT_SECONDS + 5))
done

if [ ${WAIT_SECONDS} -ge ${TIMEOUT} ]; then
    echo "   ⚠️  Timeout waiting for enhanced monitoring pods. Current status:"
    kubectl get pods -n ${NAMESPACE} -l "app=${APP_LABEL}" -o wide
    echo ""
    echo "   Check pod logs for issues:"
    echo "   kubectl logs -n ${NAMESPACE} -l app=${APP_LABEL} --tail=50"
else
    # Final verification and status
    echo ""
    echo "🎉 Enhanced Cluster-Wide Monitoring Deployment Complete!"
    echo "========================================================"
    
    echo ""
    echo "📊 Deployment Summary:"
    echo "   Namespace: ${NAMESPACE}"
    echo "   Monitoring Pods: $(kubectl get pods -n ${NAMESPACE} -l "app=${APP_LABEL}" --no-headers | wc -l)"
    echo "   Nodes Covered: $(kubectl get nodes --no-headers | wc -l)"
    
    echo ""
    echo "🔍 Enhanced Monitoring Coverage:"
    echo "   ✅ All containerized workloads"
    echo "   ✅ Host processes (kubelet, container runtime)"
    echo "   ✅ Control plane components (if present)"
    echo "   ✅ Network security events"
    echo "   ✅ File system security events"
    echo "   ✅ Process execution monitoring"
    
    echo ""
    echo "📋 Management Commands:"
    echo "   View pod status:    kubectl get pods -n ${NAMESPACE} -l app=${APP_LABEL} -o wide"
    echo "   Check logs:         kubectl logs -n ${NAMESPACE} -l app=${APP_LABEL} --tail=50"
    echo "   Scale deployment:   kubectl patch daemonset ${APP_LABEL} -n ${NAMESPACE} -p '{\"spec\":{\"template\":{\"spec\":{\"nodeSelector\":{\"monitoring\":\"enabled\"}}}}}'"
    echo "   Remove deployment:  kubectl delete -f enhanced-daemonset.yaml"
    
    echo ""
    echo "🚨 Security Note: Enhanced monitoring uses privileged containers with cluster-wide access."
    echo "   Ensure proper network policies and RBAC are configured for your environment."
fi