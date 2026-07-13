#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

image="ghcr.io/danushkastanley/pod-agent:0.1.0"

echo "Redeploying pod-agent..."

# Rebuild the image
echo "Rebuilding pod-agent image..."
docker buildx build --platform linux/amd64 -t "${image}" . --load

# Import image into k3s
echo "Importing image into k3s..."
docker save "${image}" | sudo k3s ctr images import -

# Deploy the updated daemonset
echo "Deploying updated pod-agent daemonset..."
kubectl apply -f pod-agent-daemonset.yaml

# Wait for deployment
echo "Waiting for pods to be ready..."
kubectl rollout status daemonset/pod-agent-ds --timeout=120s

# Show status
echo "Pod-agent redeployment complete."
echo "Current status:"
kubectl get pods -l app=pod-agent

echo ""
echo "To check logs:"
echo "kubectl logs -l app=pod-agent -f"
