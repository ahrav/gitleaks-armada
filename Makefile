# -------------------------------------------------------------------------------
# Variables
# -------------------------------------------------------------------------------
KIND_CLUSTER := secret-scanner

ORCHESTRATOR_APP := orchestrator
ORCHESTRATOR_IMAGE := $(ORCHESTRATOR_APP):latest

SCANNER_APP := scanner
SCANNER_IMAGE := $(SCANNER_APP):latest

K8S_MANIFESTS := k8s

# -------------------------------------------------------------------------------
# Targets
# -------------------------------------------------------------------------------
.PHONY: all build-orchestrator build-scanner docker-orchestrator docker-scanner kind-up kind-down kind-load dev-apply dev-status clean

all: build-all docker-all kind-load dev-apply

# Build targets
build-all: build-orchestrator build-scanner

build-orchestrator:
	CGO_ENABLED=0 GOOS=linux go build -o $(ORCHESTRATOR_APP) ./cmd/orchestrator

build-scanner:
	CGO_ENABLED=0 GOOS=linux go build -o $(SCANNER_APP) ./cmd/scanner

# Docker targets
docker-all: docker-orchestrator docker-scanner

docker-orchestrator:
	docker build -t $(ORCHESTRATOR_IMAGE) -f Dockerfile.orchestrator .

docker-scanner:
	docker build -t $(SCANNER_IMAGE) -f Dockerfile.scanner .

# Kind cluster management
kind-up:
	kind create cluster --name $(KIND_CLUSTER)
	kubectl cluster-info --context kind-$(KIND_CLUSTER)

kind-down:
	kind delete cluster --name $(KIND_CLUSTER)

# Load images into kind
kind-load:
	kind load docker-image $(ORCHESTRATOR_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(SCANNER_IMAGE) --name $(KIND_CLUSTER)

# Apply Kubernetes manifests
dev-apply:
	kubectl apply -f $(K8S_MANIFESTS)

# Show status
dev-status:
	kubectl get pods -o wide
	@echo "\nLeader Election Status:"
	kubectl get lease -n default

# Clean built binaries
clean:
	rm -f $(ORCHESTRATOR_APP)
	rm -f $(SCANNER_APP)

# Additional convenience targets
dev: kind-up all

# Rebuild and redeploy without recreating cluster
redeploy:
	$(MAKE) build-all
	$(MAKE) docker-all
	$(MAKE) kind-load
	$(MAKE) dev-apply
	kubectl rollout restart deployment/scanner-orchestrator
	kubectl rollout restart deployment/scanner-worker

rollout-restart:
	kubectl rollout restart deployment/scanner-orchestrator
	kubectl rollout restart deployment/scanner-worker

# View logs
logs-orchestrator:
	kubectl logs -l app=scanner-orchestrator --tail=100 -f

logs-scanner:
	kubectl logs -l app=scanner-worker --tail=100 -f

# Scale deployments
scale-orchestrator:
	kubectl scale --replicas=$(replicas) deployment/scanner-orchestrator

scale-scanner:
	kubectl scale --replicas=$(replicas) deployment/scanner-worker
