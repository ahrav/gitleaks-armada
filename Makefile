################################################################################
# Conditionally use /bin/ash in Alpine, otherwise /bin/bash
################################################################################
SHELL_PATH = /bin/ash
SHELL = $(if $(wildcard $(SHELL_PATH)),/bin/ash,/bin/bash)

################################################################################
# Variables
################################################################################

KIND_CLUSTER := secret-scanner
NAMESPACE := secret-scanner

CONTROLLER_APP := controller
CONTROLLER_IMAGE := $(CONTROLLER_APP):latest

SCANNER_APP := scanner
SCANNER_IMAGE := $(SCANNER_APP):latest

CLIENT_API_APP := client-api
CLIENT_API_IMAGE := $(CLIENT_API_APP):latest

SCANNER_GATEWAY_APP := scanner-gateway
SCANNER_GATEWAY_IMAGE := $(SCANNER_GATEWAY_APP):latest

PROMETHEUS_IMAGE := prom/prometheus:v3.1.0
GRAFANA_IMAGE := grafana/grafana:11.4.0
TEMPO_IMAGE := grafana/tempo:2.6.1
LOKI := grafana/loki:3.2.0
PROMTAIL := grafana/promtail:3.2.0
OTEL_COLLECTOR_IMAGE := otel/opentelemetry-collector-contrib:0.116.1
POSTGRES_IMAGE := postgres:17.2
KAFKA_IMAGE := bitnami/kafka:latest
ZOOKEEPER_IMAGE := bitnami/zookeeper:latest

NGINX_INGRESS_VERSION := release-1.12

K8S_MANIFESTS := k8s
CONFIG_FILE ?= config.yaml
SECRET_NAME ?= scanner-targets

# Kafka topics for reference
KAFKA_TASK_CREATED_TOPIC := task-created
KAFKA_SCANNING_TASK_TOPIC := scanning-tasks
KAFKA_RESULTS_TOPIC := results
KAFKA_PROGRESS_TOPIC := progress
KAFKA_RULES_REQUEST_TOPIC := rules-requests
KAFKA_RULES_RESPONSE_TOPIC := rules-responses
KAFKA_HIGH_PRIORITY_TASK_TOPIC := high-priority-tasks
KAFKA_JOB_LIFECYCLE_TOPIC := job-lifecycle
KAFKA_JOB_BROADCAST_TOPIC := job-broadcast
KAFKA_SCANNER_LIFECYCLE_TOPIC := scanner-lifecycle

# Postgres connection URL
POSTGRES_URL = postgres://postgres:postgres@localhost:5432/secretscanner?sslmode=disable

# Protobuf/SQLC specifics
PROTO_DIR := proto
PROTO_FILES := $(wildcard $(PROTO_DIR)/*.proto)
PROTOC_GEN_GO := $(GOPATH)/bin/protoc-gen-go
PROTOC_GEN_GO_GRPC := $(GOPATH)/bin/protoc-gen-go-grpc

CONTROLLER_PARTITIONS := 3   # Matches controller replicas
SCANNER_PARTITIONS := 5     # Matches scanner replicas


################################################################################
# Help
################################################################################

.PHONY: help dev-setup dev-brew dev-gotooling dev-docker build-all docker-all \
        dev-up dev-load dev-apply dev-status dev-down dev-apply-extras \
        kafka-setup kafka-logs kafka-topics kafka-delete kafka-restart kafka-reset \
        kafka-consumer-groups logs-controller logs-scanner create-config-secret \
        monitoring-port-forward monitoring-cleanup postgres-setup postgres-logs \
        postgres-restart postgres-delete sqlc-proto-gen proto-gen test test-coverage \
        rollout-restart rollout-restart-controller rollout-restart-scanner \
        rollout-restart-client-api clean dev-all clean-hosts verify-kong update-hosts

help:
	@echo "Usage: make <command>"
	@echo ""
	@echo "Local dev setup:"
	@echo "  dev-setup             Install brew pkgs, Go tooling, pull Docker images"
	@echo "  dev-up                Create KinD cluster + Kong ingress namespace"
	@echo "  dev-load              Load your local Docker images into the cluster"
	@echo "  dev-apply             Apply core manifests for controller/scanner/gateway"
	@echo "  dev-apply-extras      Apply Kafka, Postgres, monitoring, etc."
	@echo "  dev-down              Delete the KinD cluster"
	@echo "  dev-all               Full cycle: build, cluster up, load images, apply manifests"
	@echo "  verify-kong           Verify Kong ingress controller is working correctly"
	@echo "  update-hosts          Update hosts file to use Kong NodePort (30080)"
	@echo "  clean-hosts           Remove DNS entries from /etc/hosts file"
	@echo ""
	@echo "Build & Docker:"
	@echo "  build-all             Build all binaries (controller, scanner, client-api)"
	@echo "  docker-all            Build all Docker images"
	@echo "  proto-gen             Generate Go stubs from .proto"
	@echo "  sqlc-proto-gen        Generate code with sqlc plus proto if needed"
	@echo ""
	@echo "Kafka & Postgres:"
	@echo "  kafka-setup           Create Kafka topics inside the existing Kafka cluster"
	@echo "  kafka-logs            View logs for Kafka/Zookeeper"
	@echo "  kafka-topics          List all Kafka topics"
	@echo "  kafka-delete          Delete Kafka cluster from the namespace"
	@echo "  kafka-restart         Shortcut: delete + re-apply Kafka, re-create topics"
	@echo "  kafka-reset           Wipe out topics and re-create them"
	@echo "  postgres-setup        Deploy Postgres to the cluster"
	@echo "  postgres-logs         View Postgres logs"
	@echo "  postgres-restart      Delete & re-apply Postgres"
	@echo "  postgres-delete       Delete Postgres from cluster"
	@echo ""
	@echo "Monitoring:"
	@echo "  monitoring-port-forward  Port-forward common monitoring services (Grafana, etc.)"
	@echo "  monitoring-cleanup     Delete the monitoring deployments/services"
	@echo "  kong-port-forward     Port-forward Kong proxy for local API testing"
	@echo ""
	@echo "Misc / Advanced:"
	@echo "  logs-controller       Tail logs for the controller deployment"
	@echo "  logs-scanner          Tail logs for the scanner deployment"
	@echo "  create-config-secret  Create config YAML as secret $(SECRET_NAME)"
	@echo "  rollout-restart       Restart all main deployments (controller, scanner, gateway)"
	@echo "  test                  Run Go tests with race detection"
	@echo "  test-coverage         Run tests and produce a coverage report"

################################################################################
# 1) Developer Setup Targets
################################################################################

dev-setup: dev-brew dev-gotooling dev-docker dev-kong-deps

dev-brew:
	brew update
	brew list kind || brew install kind
	brew list kubectl || brew install kubectl
	# brew list kustomize || brew install kustomize
	# brew list watch || brew install watch
	@echo "Brew-based tooling installed or already present."

dev-gotooling:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/rakyll/hey@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install golang.org/x/tools/cmd/goimports@latest
	@echo "Go-based tools installed."

dev-docker:
	docker pull $(POSTGRES_IMAGE) || true
	docker pull $(KAFKA_IMAGE) || true
	docker pull $(ZOOKEEPER_IMAGE) || true
	docker pull $(PROMETHEUS_IMAGE) || true
	docker pull $(GRAFANA_IMAGE) || true
	docker pull $(TEMPO_IMAGE) || true
	docker pull $(LOKI) || true
	docker pull $(PROMTAIL) || true
	docker pull $(OTEL_COLLECTOR_IMAGE) || true
	@echo "Pulled common Docker images."

dev-kong-deps:
	helm repo add kong https://charts.konghq.com
	helm repo update
	@echo "Kong Helm chart repository added."


################################################################################
# 2) Build & Docker creation
################################################################################

build-all: proto-gen sqlc-proto-gen build-controller build-scanner build-client-api build-scanner-gateway

proto-gen: proto-deps
	@for p in $(PROTO_FILES); do \
		echo "Generating protobuf for $$p..."; \
		protoc --go_out=. --go_opt=paths=source_relative \
			   --go-grpc_out=. --go-grpc_opt=paths=source_relative \
			   --proto_path=. $$p; \
	done

proto-deps:
	@if [ ! -f "$(PROTOC_GEN_GO)" ]; then \
		echo "Installing protoc-gen-go..."; \
		go install google.golang.org/protobuf/cmd/protoc-gen-go@latest; \
	fi
	@if [ ! -f "$(PROTOC_GEN_GO_GRPC)" ]; then \
		echo "Installing protoc-gen-go-grpc..."; \
		go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest; \
	fi

sqlc-proto-gen:
	sqlc generate

build-controller:
	CGO_ENABLED=0 GOOS=linux go build -o $(CONTROLLER_APP) ./cmd/controller

build-scanner:
	CGO_ENABLED=0 GOOS=linux go build -o $(SCANNER_APP) ./cmd/scanner

build-client-api:
	CGO_ENABLED=0 GOOS=linux go build -o $(CLIENT_API_APP) ./cmd/api

build-scanner-gateway:
	CGO_ENABLED=0 GOOS=linux go build -o $(SCANNER_GATEWAY_APP) ./cmd/gateway

docker-all: docker-controller docker-scanner docker-client-api docker-scanner-gateway

docker-controller:
	docker build -t $(CONTROLLER_IMAGE) -f Dockerfile.controller .

docker-scanner:
	docker build -t $(SCANNER_IMAGE) -f Dockerfile.scanner .

docker-client-api:
	docker build -t $(CLIENT_API_IMAGE) -f Dockerfile.client-api .

docker-scanner-gateway:
	docker build -t $(SCANNER_GATEWAY_IMAGE) -f Dockerfile.gateway .


################################################################################
# 3) Kind cluster management
################################################################################

dev-up:
	kind create cluster --name $(KIND_CLUSTER) --config $(K8S_MANIFESTS)/kind-config.yaml
	kubectl create namespace $(NAMESPACE)
	kubectl config set-context --current --namespace=$(NAMESPACE)

	# Remove NGINX ingress controller and use Kong instead
	echo "Installing Kong Ingress Controller as the default ingress..."
	kubectl create namespace kong --dry-run=client -o yaml | kubectl apply -f -
	helm repo add kong https://charts.konghq.com
	helm repo update
	helm install kong kong/kong --namespace kong \
	  --set ingressController.enabled=true \
	  --set ingressController.installCRDs=false \
	  --set proxy.type=NodePort \
	  --set proxy.http.nodePort=30080 \
	  --set proxy.tls.nodePort=30443 \
	  --set admin.enabled=true \
	  --set admin.http.enabled=true \
	  --set env.database=off \
	  --set postgresql.enabled=false

	echo "Waiting for Kong controller to be ready..."
	kubectl wait --namespace kong \
		--for=condition=ready pod \
		--selector=app.kubernetes.io/instance=kong \
		--timeout=300s

	echo "Checking if DNS entries exist in /etc/hosts..."
	api_exists=$$(grep -q "127.0.0.1 api.local.gitleaks.armada" /etc/hosts && echo "yes" || echo "no")
	scanner_api_exists=$$(grep -q "127.0.0.1 scanner-api.local.gitleaks.armada" /etc/hosts && echo "yes" || echo "no")

	if [ "$$api_exists" = "no" ]; then \
		echo "Adding api.local.gitleaks.armada DNS entry to /etc/hosts..."; \
		echo "127.0.0.1 api.local.gitleaks.armada" | sudo tee -a /etc/hosts; \
	else \
		echo "api.local.gitleaks.armada DNS entry already exists in /etc/hosts."; \
	fi

	if [ "$$scanner_api_exists" = "no" ]; then \
		echo "Adding scanner-api.local.gitleaks.armada DNS entry to /etc/hosts..."; \
		echo "127.0.0.1 scanner-api.local.gitleaks.armada" | sudo tee -a /etc/hosts; \
	else \
		echo "scanner-api.local.gitleaks.armada DNS entry already exists in /etc/hosts."; \
	fi

	if [ "$$api_exists" = "no" ] || [ "$$scanner_api_exists" = "no" ]; then \
		echo "DNS entries added. Remember to remove them when done: sudo sed -i '' '/local.gitleaks.armada/d' /etc/hosts"; \
	fi

dev-load: dev-docker
	kind load docker-image $(CONTROLLER_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(SCANNER_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(CLIENT_API_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(SCANNER_GATEWAY_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(POSTGRES_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(KAFKA_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(ZOOKEEPER_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(PROMETHEUS_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(GRAFANA_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(TEMPO_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(LOKI) --name $(KIND_CLUSTER)
	kind load docker-image $(PROMTAIL) --name $(KIND_CLUSTER)
	kind load docker-image $(OTEL_COLLECTOR_IMAGE) --name $(KIND_CLUSTER)

dev-apply:
	kubectl apply -f $(K8S_MANIFESTS)/namespace.yaml
	kubectl apply -f $(K8S_MANIFESTS)/config.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/rbac.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/client-api.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/client-http-ingress.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/controller.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/scanner.yaml -n $(NAMESPACE)

dev-apply-extras:
	# Deploy Kafka
	kubectl apply -f $(K8S_MANIFESTS)/kafka.yaml -n $(NAMESPACE)
	# Deploy Postgres
	kubectl apply -f $(K8S_MANIFESTS)/postgres.yaml -n $(NAMESPACE)
	# Deploy monitoring stack
	kubectl apply -f $(K8S_MANIFESTS)/otel.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/prometheus.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/tempo.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/grafana.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/grafana-dashboards.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/grafana-dashboards-provisioning.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/loki.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/promtail.yaml -n $(NAMESPACE)

	@echo "Waiting for Kafka, Postgres, monitoring pods to be ready..."
	sleep 10
	kubectl wait --for=condition=ready pod -l app=zookeeper --timeout=120s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=kafka --timeout=120s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=postgres --timeout=180s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=prometheus --timeout=120s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=grafana --timeout=120s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=tempo --timeout=120s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=loki --timeout=120s -n $(NAMESPACE) || true
	@echo "Verifying Tempo connectivity..."
	kubectl run -n $(NAMESPACE) tempo-test --rm -i --restart=Never --image=busybox -- nc -zvw 1 tempo 4317 || true


dev-status:
	kubectl get pods -n $(NAMESPACE) -o wide

dev-down:
	kind delete cluster --name $(KIND_CLUSTER)

# A single shortcut target that sets up everything for a new dev
dev-all: build-all docker-all dev-up dev-load create-config-secret \
         dev-apply-extras kafka-setup postgres-setup dev-apply-scanner-gateway dev-apply


################################################################################
# Kong API Gateway
################################################################################

# Note: Kong installation is now primarily done in the dev-up target
dev-apply-kong:
	kubectl create namespace kong --dry-run=client -o yaml | kubectl apply -f -
	helm repo add kong https://charts.konghq.com
	helm repo update
	helm install kong kong/kong --namespace kong \
	  --set ingressController.enabled=true \
	  --set ingressController.installCRDs=false \
	  --set proxy.type=NodePort \
	  --set proxy.http.nodePort=30080 \
	  --set proxy.tls.nodePort=30443 \
	  --set admin.enabled=true \
	  --set admin.http.enabled=true \
	  --set env.database=off \
	  --set postgresql.enabled=false

dev-update-kong:
	helm upgrade kong kong/kong --namespace kong \
	  --set ingressController.enabled=true \
	  --set ingressController.installCRDs=false \
	  --set admin.enabled=true \
	  --set admin.http.enabled=true \
	  --set env.database=off \
	  --set postgresql.enabled=false

dev-apply-scanner-gateway:
	kubectl apply -f $(K8S_MANIFESTS)/scanner-gateway.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/scanner-gateway-ingress.yaml -n $(NAMESPACE)


################################################################################
# 4) Kafka Targets
################################################################################

kafka-setup:
	@echo "Waiting for Zookeeper to be ready..."
	kubectl wait --for=condition=ready pod -l app=zookeeper --timeout=120s -n $(NAMESPACE)
	@echo "Waiting for Kafka to be ready..."
	kubectl wait --for=condition=ready pod -l app=kafka --timeout=120s -n $(NAMESPACE)
	@echo "Creating Kafka topics..."
	# Controller -> Scanner topics (use SCANNER_PARTITIONS)
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--create --if-not-exists \
			--topic $(KAFKA_TASK_CREATED_TOPIC) \
			--bootstrap-server localhost:9092 \
			--partitions $(SCANNER_PARTITIONS) \
			--replication-factor 1

	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--create --if-not-exists \
			--topic $(KAFKA_RULES_REQUEST_TOPIC) \
			--bootstrap-server localhost:9092 \
			--partitions $(SCANNER_PARTITIONS) \
			--replication-factor 1

	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--create --if-not-exists \
			--topic $(KAFKA_HIGH_PRIORITY_TASK_TOPIC) \
			--bootstrap-server localhost:9092 \
			--partitions $(SCANNER_PARTITIONS) \
			--replication-factor 1

	# Scanner -> Controller topics (use CONTROLLER_PARTITIONS)
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--create --if-not-exists \
			--topic $(KAFKA_SCANNING_TASK_TOPIC) \
			--bootstrap-server localhost:9092 \
			--partitions $(CONTROLLER_PARTITIONS) \
			--replication-factor 1

	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--create --if-not-exists \
			--topic $(KAFKA_RESULTS_TOPIC) \
			--bootstrap-server localhost:9092 \
			--partitions $(CONTROLLER_PARTITIONS) \
			--replication-factor 1

	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--create --if-not-exists \
			--topic $(KAFKA_PROGRESS_TOPIC) \
			--bootstrap-server localhost:9092 \
			--partitions $(CONTROLLER_PARTITIONS) \
			--replication-factor 1

	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--create --if-not-exists \
			--topic $(KAFKA_RULES_RESPONSE_TOPIC) \
			--bootstrap-server localhost:9092 \
			--partitions $(CONTROLLER_PARTITIONS) \
			--replication-factor 1

	# Job lifecycle topic (use CONTROLLER_PARTITIONS since job events are primarily controller-focused)
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--create --if-not-exists \
			--topic $(KAFKA_JOB_LIFECYCLE_TOPIC) \
			--bootstrap-server localhost:9092 \
			--partitions $(CONTROLLER_PARTITIONS) \
			--replication-factor 1

	# Create broadcast topic for job events that need to reach all scanners
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--create --if-not-exists \
			--topic $(KAFKA_JOB_BROADCAST_TOPIC) \
			--bootstrap-server localhost:9092 \
			--partitions $(SCANNER_PARTITIONS) \
			--replication-factor 1

	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--create --if-not-exists \
			--topic $(KAFKA_SCANNER_LIFECYCLE_TOPIC) \
			--bootstrap-server localhost:9092 \
			--partitions $(SCANNER_PARTITIONS) \
			--replication-factor 1

kafka-logs:
	@echo "Showing Kafka logs:"
	kubectl logs -l app=kafka -n $(NAMESPACE) --tail=100 -f
	@echo ""
	@echo "Showing Zookeeper logs:"
	kubectl logs -l app=zookeeper -n $(NAMESPACE) --tail=100 -f

kafka-topics:
	@echo "Listing Kafka topics:"
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--list \
			--bootstrap-server localhost:9092

	@echo ""
	@echo "Describing topic details:"
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--describe \
			--bootstrap-server localhost:9092

kafka-consumer-groups:
	@echo "Checking consumer group status..."
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-consumer-groups.sh \
		--bootstrap-server localhost:9092 \
		--describe \
		--all-groups

kafka-delete:
	kubectl delete deployment kafka zookeeper -n $(NAMESPACE) || true
	kubectl delete svc kafka zookeeper -n $(NAMESPACE) || true

kafka-restart: kafka-delete
	@echo "Re-applying Kafka manifests..."
	kubectl apply -f $(K8S_MANIFESTS)/kafka.yaml -n $(NAMESPACE)
	@echo "Waiting for Kafka pods..."
	sleep 10
	kubectl wait --for=condition=ready pod -l app=zookeeper --timeout=120s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=kafka --timeout=120s -n $(NAMESPACE) || true
	@echo "Re-creating Kafka topics..."
	$(MAKE) kafka-setup
	@echo "Kafka restarted."

kafka-reset: kafka-delete-topics kafka-setup
	@echo "All Kafka topics deleted and re-created."

kafka-delete-topics:
	@echo "Deleting Kafka topics..."
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--bootstrap-server localhost:9092 \
			--delete \
			--topic $(KAFKA_TASK_CREATED_TOPIC) || true

	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--bootstrap-server localhost:9092 \
			--delete \
			--topic $(KAFKA_RULES_REQUEST_TOPIC) || true

	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--bootstrap-server localhost:9092 \
			--delete \
			--topic $(KAFKA_HIGH_PRIORITY_TASK_TOPIC) || true

	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--bootstrap-server localhost:9092 \
			--delete \
			--topic $(KAFKA_SCANNING_TASK_TOPIC) || true

	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--bootstrap-server localhost:9092 \
			--delete \
			--topic $(KAFKA_RESULTS_TOPIC) || true

	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--bootstrap-server localhost:9092 \
			--delete \
			--topic $(KAFKA_PROGRESS_TOPIC) || true

	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--bootstrap-server localhost:9092 \
			--delete \
			--topic $(KAFKA_RULES_RESPONSE_TOPIC) || true

	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--bootstrap-server localhost:9092 \
			--delete \
			--topic $(KAFKA_JOB_LIFECYCLE_TOPIC) || true

	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--bootstrap-server localhost:9092 \
			--delete \
			--topic $(KAFKA_JOB_BROADCAST_TOPIC) || true

	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- \
		/opt/bitnami/kafka/bin/kafka-topics.sh \
			--bootstrap-server localhost:9092 \
			--delete \
			--topic $(KAFKA_SCANNER_LIFECYCLE_TOPIC) || true


################################################################################
# 5) Postgres Targets
################################################################################

postgres-setup:
	@echo "Deploying PostgreSQL..."
	docker pull $(POSTGRES_IMAGE)
	kind load docker-image $(POSTGRES_IMAGE) --name $(KIND_CLUSTER)
	kubectl apply -f $(K8S_MANIFESTS)/postgres.yaml -n $(NAMESPACE)
	@echo "Waiting for PostgreSQL to be ready..."
	sleep 5
	kubectl wait --for=condition=ready pod -l app=postgres --timeout=180s -n $(NAMESPACE) || true

postgres-logs:
	kubectl logs -l app=postgres -n $(NAMESPACE) --tail=100 -f

postgres-delete:
	kubectl delete -f $(K8S_MANIFESTS)/postgres.yaml -n $(NAMESPACE) || true

postgres-restart: postgres-delete postgres-setup

################################################################################
# 6) Monitoring Targets
################################################################################

monitoring-port-forward:
	@echo "Access Prometheus at http://localhost:9090"
	@echo "Access Grafana at http://localhost:3000 (user: admin / pass: admin)"
	@echo "Access Tempo at http://localhost:3200"
	@echo "Access OTel Collector at localhost:4317 (gRPC), 4318 (HTTP), 8889 (metrics), 55679 (zPages)"
	kubectl port-forward -n $(NAMESPACE) svc/prometheus 9090:9090 & \
	kubectl port-forward -n $(NAMESPACE) svc/grafana 3000:3000 & \
	kubectl port-forward -n $(NAMESPACE) svc/tempo 3200:3200 & \
	kubectl port-forward -n $(NAMESPACE) svc/otel-collector 4317:4317 & \
	kubectl port-forward -n $(NAMESPACE) svc/otel-collector 4318:4318 & \
	kubectl port-forward -n $(NAMESPACE) svc/otel-collector 8889:8889 & \
	kubectl port-forward -n $(NAMESPACE) svc/otel-collector 55679:55679

monitoring-cleanup:
	kubectl delete -f $(K8S_MANIFESTS)/otel.yaml -n $(NAMESPACE) || true
	kubectl delete -f $(K8S_MANIFESTS)/prometheus.yaml -n $(NAMESPACE) || true
	kubectl delete -f $(K8S_MANIFESTS)/tempo.yaml -n $(NAMESPACE) || true
	kubectl delete -f $(K8S_MANIFESTS)/grafana.yaml -n $(NAMESPACE) || true
	kubectl delete -f $(K8S_MANIFESTS)/grafana-dashboards.yaml -n $(NAMESPACE) || true
	kubectl delete -f $(K8S_MANIFESTS)/grafana-dashboards-provisioning.yaml -n $(NAMESPACE) || true
	kubectl delete -f $(K8S_MANIFESTS)/loki.yaml -n $(NAMESPACE) || true
	kubectl delete -f $(K8S_MANIFESTS)/promtail.yaml -n $(NAMESPACE) || true

################################################################################
# Logs and misc
################################################################################

logs-controller:
	kubectl logs -l app=controller -n $(NAMESPACE) --tail=100 -f

logs-scanner:
	kubectl logs -l app=scanner -n $(NAMESPACE) --tail=100 -f

logs-scanner-gateway:
	kubectl logs -l app=scanner-gateway -n $(NAMESPACE) --tail=100 -f

create-config-secret:
	@echo "Creating or updating config secret $(SECRET_NAME) from $(CONFIG_FILE)..."
	kubectl create secret generic $(SECRET_NAME) \
		--from-file=config.yaml=$(CONFIG_FILE) \
		--namespace=$(NAMESPACE) \
		--dry-run=client -o yaml | kubectl apply -f -

client-api-port-forward:
	@echo "Port forwarding Client API to localhost:8080..."
	kubectl port-forward -n $(NAMESPACE) svc/client-api-svc 8080:80 &

################################################################################
# Rollout restarts
################################################################################

rollout-restart: rollout-restart-controller rollout-restart-scanner rollout-restart-client-api rollout-restart-scanner-gateway

rollout-restart-controller:
	kubectl rollout restart deployment/controller -n $(NAMESPACE)

rollout-restart-scanner:
	kubectl rollout restart deployment/scanner -n $(NAMESPACE)

rollout-restart-client-api:
	kubectl rollout restart deployment/client-api -n $(NAMESPACE)

rollout-restart-scanner-gateway:
	kubectl rollout restart deployment/scanner-gateway -n $(NAMESPACE)

################################################################################
# Testing and cleanup
################################################################################

test:
	@echo "Running tests..."
	GOEXPERIMENT=synctest go test -v -race -parallel=10 ./...

test-coverage:
	@echo "Running tests with coverage..."
	GOEXPERIMENT=synctest go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

clean:
	rm -f $(CONTROLLER_APP) $(SCANNER_APP) $(CLIENT_API_APP) $(SCANNER_GATEWAY_APP)
	@echo "Cleaned up local binaries."

kong-port-forward:
	@echo "Port forwarding Kong proxy service to localhost:8000 (HTTP) and localhost:9000 (gRPC)"
	kubectl port-forward -n kong svc/kong-proxy 8000:80 9000:9080 &

################################################################################
# Utility Targets
################################################################################

# Remove the DNS entries from /etc/hosts file
clean-hosts:
	@echo "Removing gitleaks.armada DNS entries from /etc/hosts..."
	sudo sed -i '' '/local.gitleaks.armada/d' /etc/hosts
	@echo "DNS entries removed successfully."

verify-kong:
	@echo "Verifying Kong ingress controller setup..."
	@echo "1. Checking if Kong pods are running..."
	kubectl get pods -n kong

	@echo "\n2. Checking ingress classes..."
	kubectl get ingressclass

	@echo "\n3. Checking Kong proxy service..."
	kubectl get svc -n kong kong-kong-proxy -o wide

	@echo "\n4. Setting up port-forwarding to access Kong..."
	kubectl port-forward --namespace kong service/kong-kong-proxy 30080:80 > /dev/null 2>&1 &
	PF_PID=$$!
	echo "Port forwarding started with PID: $$PF_PID"
	sleep 3

	@echo "\n5. Testing connection to Kong proxy..."
	curl -v http://localhost:30080 || true

	@echo "\n6. Testing connection to api.local.gitleaks.armada..."
	curl -v http://api.local.gitleaks.armada:30080 || true

	@echo "\nKong verification complete. You may need to adjust your hosts file"
	@echo "or run 'make update-hosts' to update your DNS entries to point to port 30080"
	@echo "Kill the port forwarding with: kill $$PF_PID"

# Update hosts file to use the nodePort 30080 instead of default port 80
update-hosts:
	@echo "Updating hosts file to use Kong NodePort..."
	sudo sed -i '' '/local.gitleaks.armada/d' /etc/hosts
	echo "127.0.0.1 api.local.gitleaks.armada" | sudo tee -a /etc/hosts
	echo "127.0.0.1 scanner-api.local.gitleaks.armada" | sudo tee -a /etc/hosts
	@echo "Hosts file updated."
	@echo "Remember to use URLs with port 30080: http://api.local.gitleaks.armada:30080/v1/scanners/groups"
