# -------------------------------------------------------------------------------
# Variables
# -------------------------------------------------------------------------------
KIND_CLUSTER := secret-scanner

CONTROLLER_APP := controller
CONTROLLER_IMAGE := $(CONTROLLER_APP):latest

SCANNER_APP := scanner
SCANNER_IMAGE := $(SCANNER_APP):latest

K8S_MANIFESTS := k8s

# Protobuf variables
PROTO_DIR := proto
PROTO_FILES := $(wildcard $(PROTO_DIR)/*/*.proto)
PROTOC_GEN_GO := $(GOPATH)/bin/protoc-gen-go
PROTOC_GEN_GO_GRPC := $(GOPATH)/bin/protoc-gen-go-grpc

# Kafka variables
KAFKA_IMAGE := bitnami/kafka:latest
ZOOKEEPER_IMAGE := bitnami/zookeeper:latest

# Config variables
CONFIG_FILE ?= config.yaml
SECRET_NAME ?= scanner-targets
NAMESPACE ?= default

# -------------------------------------------------------------------------------
# Targets
# -------------------------------------------------------------------------------
.PHONY: all build-controller build-scanner docker-controller docker-scanner kind-up kind-down kind-load dev-apply dev-status clean proto proto-gen kafka-setup kafka-logs kafka-topics kafka-restart kafka-delete create-config-secret

all: build-all docker-all kind-load kafka-setup dev-apply create-config-secret

# Build targets
build-all: proto-gen build-controller build-scanner

build-controller:
	CGO_ENABLED=0 GOOS=linux go build -o $(CONTROLLER_APP) ./cmd/controller

build-scanner:
	CGO_ENABLED=0 GOOS=linux go build -o $(SCANNER_APP) ./cmd/scanner

# Docker targets
docker-all: docker-controller docker-scanner

docker-controller:
	docker build -t $(CONTROLLER_IMAGE) -f Dockerfile.controller .

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
	kind load docker-image $(CONTROLLER_IMAGE) --name $(KIND_CLUSTER)
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
	rm -f $(CONTROLLER_APP)
	rm -f $(SCANNER_APP)
	kubectl delete deployment kafka zookeeper || true

# Additional convenience targets
dev: kind-up all

# Rebuild and redeploy without recreating cluster
redeploy: build-all docker-all kind-load dev-apply
	kubectl rollout restart deployment/scanner-controller
	kubectl rollout restart deployment/scanner-worker

rollout-restart:
	kubectl rollout restart deployment/scanner-controller
	kubectl rollout restart deployment/scanner-worker

# View logs
logs-controller:
	kubectl logs -l app=scanner-controller --tail=100 -f

logs-scanner:
	kubectl logs -l app=scanner-worker --tail=100 -f

# Scale deployments
scale-controller:
	kubectl scale --replicas=$(replicas) deployment/scanner-controller

scale-scanner:
	kubectl scale --replicas=$(replicas) deployment/scanner-worker

# Proto targets
proto: proto-deps proto-gen

proto-deps:
	@if [ ! -f "$(PROTOC_GEN_GO)" ]; then \
		echo "Installing protoc-gen-go..."; \
		go install google.golang.org/protobuf/cmd/protoc-gen-go@latest; \
	fi

proto-gen:
	@for proto in $(PROTO_FILES); do \
		dir=$$(dirname $$proto); \
		pkg=$$(basename $$dir); \
		echo "Generating protobuf code for $$proto..."; \
		protoc --go_out=. --go_opt=paths=source_relative \
			--go_opt=M$$proto=github.com/ahrav/gitleaks-armada/proto/$$pkg \
			$$proto; \
	done

# Kafka targets
kafka-setup:
	@echo "Pulling Kafka and Zookeeper images..."
	docker pull $(KAFKA_IMAGE)
	docker pull $(ZOOKEEPER_IMAGE)
	@echo "Loading images into kind cluster..."
	kind load docker-image $(KAFKA_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(ZOOKEEPER_IMAGE) --name $(KIND_CLUSTER)
	@echo "Waiting for pods to be ready..."
	kubectl wait --for=condition=ready pod -l app=zookeeper --timeout=120s || true
	kubectl wait --for=condition=ready pod -l app=kafka --timeout=120s || true

kafka-logs:
	@echo "Kafka logs:"
	kubectl logs -l app=kafka --tail=100 -f
	@echo "\nZookeeper logs:"
	kubectl logs -l app=zookeeper --tail=100 -f

kafka-topics:
	kubectl exec -it deployment/kafka -- /opt/kafka/bin/kafka-topics.sh --list --bootstrap-server localhost:9092

kafka-delete:
	kubectl delete deployment kafka zookeeper || true
	kubectl delete service kafka zookeeper || true

kafka-restart: kafka-delete
	@echo "Loading Kafka images..."
	kind load docker-image $(KAFKA_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(ZOOKEEPER_IMAGE) --name $(KIND_CLUSTER)
	@echo "Applying Kafka manifests..."
	kubectl apply -f k8s/kafka.yaml
	@echo "Waiting for pods to be ready..."
	sleep 5  # Give k8s a moment to create the pods
	kubectl wait --for=condition=ready pod -l app=zookeeper --timeout=120s || true
	kubectl wait --for=condition=ready pod -l app=kafka --timeout=120s || true
	@echo "Kafka and Zookeeper restarted"

# Create config secret
create-config-secret:
	@echo "Creating secret from config file..."
	@kubectl create secret generic $(SECRET_NAME) \
		--from-file=config.yaml=$(CONFIG_FILE) \
		--namespace=$(NAMESPACE) \
		--dry-run=client -o yaml | kubectl apply -f -

