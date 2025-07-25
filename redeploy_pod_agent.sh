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

echo "🔄 Redeploying pod-agent with container identification fixes..."

# Delete the existing daemonset
echo "📉 Removing existing pod-agent daemonset..."
kubectl delete daemonset pod-agent-ds --ignore-not-found=true

# Wait for pods to terminate
echo "⏳ Waiting for pod-agent pods to terminate..."
sleep 5

# Rebuild the image
echo "🔨 Rebuilding pod-agent image..."
docker build -t pod-agent:latest .

# Import image into k3s
echo "📦 Importing image into k3s..."
docker save pod-agent:latest | sudo k3s ctr images import -

# Deploy the updated daemonset
echo "🚀 Deploying updated pod-agent daemonset..."
kubectl apply -f pod-agent-daemonset.yaml

# Wait for deployment
echo "⏳ Waiting for pods to be ready..."
kubectl rollout status daemonset/pod-agent-ds --timeout=120s

# Show status
echo "✅ Pod-agent redeployment complete!"
echo "📊 Current status:"
kubectl get pods -l app=pod-agent

echo ""
echo "🔍 To check logs:"
echo "kubectl logs -l app=pod-agent -f"