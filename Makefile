# -------------------------------------------------------------------------------
# Variables - Adjust these for your environment
# -------------------------------------------------------------------------------

APP_NAME := secret-scanner
IMAGE_NAME := $(APP_NAME):latest
KIND_CLUSTER := secret-scanner

PROTO_DIR := ./proto
PROTO_FILE := cluster.proto
CMD_DIR := ./cmd/server

GO_OUT_DIR := .

K8S_MANIFESTS := k8s
# This assumes you have a deployment.yaml and service.yaml in ./k8s directory.

# -------------------------------------------------------------------------------
# Targets
# -------------------------------------------------------------------------------

.PHONY: all proto build docker kind-up kind-down kind-load dev-apply dev-status clean

all: proto build docker kind-load dev-apply

## Generate code from Protobuf files
proto:
	protoc \
		--go_out=$(GO_OUT_DIR) \
		--go-grpc_out=$(GO_OUT_DIR) \
		--go_opt=paths=source_relative \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/$(PROTO_FILE)

## Build the Go binary for Linux (so it can be used in the container)
build:
	CGO_ENABLED=0 GOOS=linux go build -o $(APP_NAME) $(CMD_DIR)

## Build Docker image from Dockerfile
docker: build
	docker build -t $(IMAGE_NAME) .

## Create a local kind cluster
kind-up:
	kind create cluster --name $(KIND_CLUSTER)
	kubectl cluster-info --context kind-$(KIND_CLUSTER)

## Delete the kind cluster
kind-down:
	kind delete cluster --name $(KIND_CLUSTER)

## Load the Docker image into the kind cluster
kind-load:
	kind load docker-image $(IMAGE_NAME) --name $(KIND_CLUSTER)

## Apply Kubernetes manifests (Deployment, Service)
dev-apply:
	kubectl apply -f $(K8S_MANIFESTS)/deployment.yaml
	kubectl apply -f $(K8S_MANIFESTS)/service.yaml

## Show the status of Pods
dev-status:
	kubectl get pods -o wide

## Clean up the local binary
clean:
	rm -f $(APP_NAME)

# Additional convenience targets:

# Run all steps to get dev environment up and running
dev: kind-up all
# This will:
# 1. Ensure cluster is up (kind-up)
# 2. Run `all` which does proto/build/docker/kind-load/dev-apply

# Rebuild and reapply without recreating the cluster or regenerating protos
redeploy:
	$(MAKE) build
	$(MAKE) docker
	$(MAKE) kind-load
	$(MAKE) dev-apply

## Run locally (not in container/k8s), useful for debugging locally
run:
	go run $(CMD_DIR)

## If you want to scale deployments, etc.
scale:
	kubectl scale --replicas=2 deployment/$(APP_NAME)
