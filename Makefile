# -------------------------------------------------------------------------------
# Variables
# -------------------------------------------------------------------------------
KIND_CLUSTER := secret-scanner
NAMESPACE := secret-scanner

CONTROLLER_APP := controller
CONTROLLER_IMAGE := $(CONTROLLER_APP):latest

SCANNER_APP := scanner
SCANNER_IMAGE := $(SCANNER_APP):latest

# Add monitoring variables
PROMETHEUS_IMAGE := prom/prometheus:v2.55.0
GRAFANA_IMAGE := grafana/grafana:11.3.0

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

# Add to Variables section
POSTGRES_IMAGE := postgres:17.2

# -------------------------------------------------------------------------------
# Targets
# -------------------------------------------------------------------------------
.PHONY: all build-controller build-scanner docker-controller docker-scanner kind-up kind-down kind-load dev-apply dev-status clean proto proto-gen kafka-setup kafka-logs kafka-topics kafka-restart kafka-delete create-config-secret monitoring-setup monitoring-port-forward monitoring-cleanup postgres-setup postgres-logs postgres-restart postgres-delete

all: build-all docker-all kind-load kafka-setup postgres-setup dev-apply create-config-secret monitoring-setup

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
	kubectl create namespace $(NAMESPACE)
	kubectl config set-context --current --namespace=$(NAMESPACE)
	kubectl cluster-info --context kind-$(KIND_CLUSTER)

kind-down:
	kind delete cluster --name $(KIND_CLUSTER)

kind-load-controller:
	kind load docker-image $(CONTROLLER_IMAGE) --name $(KIND_CLUSTER)

kind-load-scanner:
	kind load docker-image $(SCANNER_IMAGE) --name $(KIND_CLUSTER)

# Load images into kind
kind-load: kind-load-controller kind-load-scanner

# Apply Kubernetes manifests
dev-apply:
	kubectl apply -f $(K8S_MANIFESTS)/namespace.yaml
	kubectl apply -f $(K8S_MANIFESTS)/config.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/rbac.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/kafka.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/controller.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/scanner.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/prometheus.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/grafana.yaml -n $(NAMESPACE)

# Show status
dev-status:
	kubectl get pods -n $(NAMESPACE) -o wide
	@echo "\nLeader Election Status:"
	kubectl get lease -n $(NAMESPACE)

# Clean built binaries
clean:
	rm -f $(CONTROLLER_APP)
	rm -f $(SCANNER_APP)
	kubectl delete deployment kafka zookeeper -n $(NAMESPACE) || true
	kubectl delete -f $(K8S_MANIFESTS)/prometheus.yaml -n $(NAMESPACE) || true
	kubectl delete -f $(K8S_MANIFESTS)/grafana.yaml -n $(NAMESPACE) || true
	kubectl delete -f $(K8S_MANIFESTS)/postgres.yaml -n $(NAMESPACE) || true

# Additional convenience targets
dev: kind-up all

redeploy-controller: build-controller docker-controller kind-load-controller
	kubectl rollout restart deployment/scanner-controller -n $(NAMESPACE)

redeploy-scanner: build-scanner docker-scanner kind-load-scanner
	kubectl rollout restart deployment/scanner-worker -n $(NAMESPACE)

# Rebuild and redeploy without recreating cluster
redeploy: build-all docker-all kind-load dev-apply
	kubectl rollout restart deployment/scanner-controller -n $(NAMESPACE)
	kubectl rollout restart deployment/scanner-worker -n $(NAMESPACE)

rollout-restart:
	kubectl rollout restart deployment/scanner-controller -n $(NAMESPACE)
	kubectl rollout restart deployment/scanner-worker -n $(NAMESPACE)

# View logs
logs-controller:
	kubectl logs -l app=scanner-controller -n $(NAMESPACE) --tail=100 -f

logs-scanner:
	kubectl logs -l app=scanner-worker -n $(NAMESPACE) --tail=100 -f

# Scale deployments
scale-controller:
	kubectl scale deployment/scanner-controller -n $(NAMESPACE) --replicas=$(replicas)

scale-scanner:
	kubectl scale deployment/scanner-worker -n $(NAMESPACE) --replicas=$(replicas)

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
	kubectl wait --for=condition=ready pod -l app=zookeeper --timeout=120s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=kafka --timeout=120s -n $(NAMESPACE) || true

kafka-logs:
	@echo "Kafka logs:"
	kubectl logs -l app=kafka -n $(NAMESPACE) --tail=100 -f
	@echo "\nZookeeper logs:"
	kubectl logs -l app=zookeeper -n $(NAMESPACE) --tail=100 -f

kafka-topics:
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/kafka/bin/kafka-topics.sh --list --bootstrap-server localhost:9092

kafka-delete:
	kubectl delete deployment kafka zookeeper -n $(NAMESPACE) || true
	kubectl delete service kafka zookeeper -n $(NAMESPACE) || true

kafka-restart: kafka-delete
	@echo "Loading Kafka images..."
	kind load docker-image $(KAFKA_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(ZOOKEEPER_IMAGE) --name $(KIND_CLUSTER)
	@echo "Applying Kafka manifests..."
	kubectl apply -f k8s/kafka.yaml -n $(NAMESPACE)
	@echo "Waiting for pods to be ready..."
	sleep 5  # Give k8s a moment to create the pods
	kubectl wait --for=condition=ready pod -l app=zookeeper --timeout=120s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=kafka --timeout=120s -n $(NAMESPACE) || true
	@echo "Kafka and Zookeeper restarted"

# Create config secret
create-config-secret:
	@echo "Creating secret from config file..."
	@kubectl create secret generic $(SECRET_NAME) \
		--from-file=config.yaml=$(CONFIG_FILE) \
		--namespace=$(NAMESPACE) \
		--dry-run=client -o yaml | kubectl apply -f -

# Add monitoring targets
monitoring-setup:
	@echo "Loading monitoring images..."
	docker pull $(PROMETHEUS_IMAGE)
	docker pull $(GRAFANA_IMAGE)
	kind load docker-image $(PROMETHEUS_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(GRAFANA_IMAGE) --name $(KIND_CLUSTER)
	kubectl apply -f $(K8S_MANIFESTS)/prometheus.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/grafana.yaml -n $(NAMESPACE)

monitoring-port-forward:
	@echo "Access Prometheus at http://localhost:9090"
	@echo "Access Grafana at http://localhost:3000 (admin/admin)"
	kubectl port-forward -n $(NAMESPACE) svc/prometheus 9090:9090 & \
	kubectl port-forward -n $(NAMESPACE) svc/grafana 3000:3000

monitoring-cleanup:
	kubectl delete -f $(K8S_MANIFESTS)/prometheus.yaml -n $(NAMESPACE) || true
	kubectl delete -f $(K8S_MANIFESTS)/grafana.yaml -n $(NAMESPACE) || true

# Add new postgres targets
postgres-setup:
	@echo "Setting up PostgreSQL..."
	docker pull $(POSTGRES_IMAGE)
	kind load docker-image $(POSTGRES_IMAGE) --name $(KIND_CLUSTER)
	kubectl apply -f $(K8S_MANIFESTS)/postgres.yaml -n $(NAMESPACE)
	@echo "Waiting for PostgreSQL to be ready..."
	kubectl wait --for=condition=ready pod -l app=postgres --timeout=120s -n $(NAMESPACE)

postgres-logs:
	kubectl logs -l app=postgres -n $(NAMESPACE) --tail=100 -f

postgres-delete:
	kubectl delete -f $(K8S_MANIFESTS)/postgres.yaml -n $(NAMESPACE) || true

postgres-restart: postgres-delete postgres-setup

