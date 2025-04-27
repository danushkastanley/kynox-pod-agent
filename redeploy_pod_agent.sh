#!/bin/bash

# Script to rebuild, import, and redeploy the pod-agent
# Run this script from the pod-agent directory on the Ubuntu machine

set -e # Exit immediately if a command exits with a non-zero status.

IMAGE_NAME="pod-agent"
IMAGE_TAG="latest"
K3S_IMAGE_NAME="docker.io/library/${IMAGE_NAME}:${IMAGE_TAG}"
TEMP_TAR_FILE="${IMAGE_NAME}-${IMAGE_TAG}.tar"
DAEMONSET_FILE="pod-agent-daemonset.yaml"

echo "--- Building Docker image ${IMAGE_NAME}:${IMAGE_TAG}... ---"
docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" .

echo "--- Removing old image from k3s containerd (if exists)... ---"
sudo k3s ctr images rm "${K3S_IMAGE_NAME}" || echo "Image not found in k3s, continuing..."

echo "--- Exporting image ${IMAGE_NAME}:${IMAGE_TAG} from Docker... ---"
docker save "${IMAGE_NAME}:${IMAGE_TAG}" -o "${TEMP_TAR_FILE}"

echo "--- Importing image into k3s containerd... ---"
sudo k3s ctr images import "${TEMP_TAR_FILE}"

echo "--- Cleaning up temporary tar file... ---"
rm "${TEMP_TAR_FILE}"

echo "--- Applying Kubernetes DaemonSet ${DAEMONSET_FILE}... ---"
kubectl apply -f "${DAEMONSET_FILE}"

echo "--- Done. Monitor pod status with: kubectl get pods -l app=pod-agent -w ---"
