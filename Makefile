# -------------------------------------------------------------------------------
# Variables
# -------------------------------------------------------------------------------
KIND_CLUSTER := secret-scanner
NAMESPACE := secret-scanner

CONTROLLER_APP := controller
CONTROLLER_IMAGE := $(CONTROLLER_APP):latest

SCANNER_APP := scanner
SCANNER_IMAGE := $(SCANNER_APP):latest

API_GATEWAY_APP := api-gateway
API_GATEWAY_IMAGE := $(API_GATEWAY_APP):latest

PROMETHEUS_IMAGE := prom/prometheus:v3.1.0
GRAFANA_IMAGE := grafana/grafana:11.4.0
TEMPO_IMAGE := grafana/tempo:2.6.1
LOKI            := grafana/loki:3.2.0
PROMTAIL        := grafana/promtail:3.2.0
OTEL_COLLECTOR_IMAGE := otel/opentelemetry-collector-contrib:0.116.1
POSTGRES_IMAGE := postgres:17.2
KAFKA_IMAGE := bitnami/kafka:latest
ZOOKEEPER_IMAGE := bitnami/zookeeper:latest
NGINX_INGRESS_VERSION := release-1.12

K8S_MANIFESTS := k8s

# Protobuf variables
PROTO_DIR := proto
PROTO_FILES := $(wildcard $(PROTO_DIR)/*.proto)
PROTOC_GEN_GO := $(GOPATH)/bin/protoc-gen-go
PROTOC_GEN_GO_GRPC := $(GOPATH)/bin/protoc-gen-go-grpc


# Config variables
CONFIG_FILE ?= config.yaml
SECRET_NAME ?= scanner-targets

# Add to Variables section
KAFKA_ENUMERATION_TASK_TOPIC := enumeration-tasks
KAFKA_SCANNING_TASK_TOPIC := scanning-tasks
KAFKA_RESULTS_TOPIC := results
KAFKA_PROGRESS_TOPIC := progress
KAFKA_RULES_REQUEST_TOPIC := rules-requests
KAFKA_RULES_RESPONSE_TOPIC := rules-responses
KAFKA_HIGH_PRIORITY_TASK_TOPIC := high-priority-tasks
KAFKA_JOB_METRICS_TOPIC := job-metrics
POSTGRES_URL = postgres://postgres:postgres@localhost:5432/secretscanner?sslmode=disable

# -------------------------------------------------------------------------------
# Targets
# -------------------------------------------------------------------------------
.PHONY: all build-all docker-all kind-up kind-down kind-load dev-apply dev-status clean proto proto-gen kafka-setup kafka-logs kafka-topics kafka-restart kafka-delete kafka-consumer-groups kafka-delete-topics kafka-reset create-config-secret monitoring-setup monitoring-port-forward monitoring-cleanup postgres-setup postgres-logs postgres-restart postgres-delete sqlc-proto-gen rollout-restart-controller rollout-restart-scanner rollout-restart-api-gateway rollout-restart test test-coverage setup-local-ingress

all: build-all docker-all kind-load postgres-setup kafka-setup create-config-secret monitoring-setup dev-apply

# Build targets
build-all: proto-gen sqlc-proto-gen build-controller build-scanner build-api-gateway

build-controller:
	CGO_ENABLED=0 GOOS=linux go build -o $(CONTROLLER_APP) ./cmd/controller

build-scanner:
	CGO_ENABLED=0 GOOS=linux go build -o $(SCANNER_APP) ./cmd/scanner

build-api-gateway:
	CGO_ENABLED=0 GOOS=linux go build -o $(API_GATEWAY_APP) ./cmd/api

# Docker targets
docker-all: docker-controller docker-scanner docker-api-gateway

docker-controller:
	docker build -t $(CONTROLLER_IMAGE) -f Dockerfile.controller .

docker-scanner:
	docker build -t $(SCANNER_IMAGE) -f Dockerfile.scanner .

docker-api-gateway:
	docker build -t $(API_GATEWAY_IMAGE) -f Dockerfile.api-gateway .

# Kind cluster management
kind-up:
	kind create cluster --name $(KIND_CLUSTER) --config k8s/kind-config.yaml
	kubectl create namespace $(NAMESPACE)
	kubectl config set-context --current --namespace=$(NAMESPACE)
	$(MAKE) setup-local-ingress

kind-down:
	kind delete cluster --name $(KIND_CLUSTER)

kind-load: kind-load-controller kind-load-scanner kind-load-api-gateway

kind-load-controller:
	kind load docker-image $(CONTROLLER_IMAGE) --name $(KIND_CLUSTER)

kind-load-scanner:
	kind load docker-image $(SCANNER_IMAGE) --name $(KIND_CLUSTER)

kind-load-api-gateway:
	kind load docker-image $(API_GATEWAY_IMAGE) --name $(KIND_CLUSTER)

# Ingress setup
setup-local-ingress:
	echo "Installing NGINX Ingress Controller for local development..."
	kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/$(NGINX_INGRESS_VERSION)/deploy/static/provider/kind/deploy.yaml

	echo "Waiting for ingress-nginx namespace..."
	sleep 10  # Give k8s time to create the namespace

	echo "Waiting for NGINX Ingress Controller deployment to be available..."
	kubectl wait --namespace ingress-nginx \
		--for=condition=available deployment ingress-nginx-controller \
		--timeout=300s

	kubectl wait --namespace ingress-nginx \
		--for=condition=ready pod \
		--selector=app.kubernetes.io/component=controller \
		--timeout=120s

	echo "Checking if DNS entry already exists in /etc/hosts..."
	if ! grep -q "127.0.0.1 api.local.gitleaks.armada" /etc/hosts; then \
		echo "Adding local DNS entry to /etc/hosts..."; \
		echo "127.0.0.1 api.local.gitleaks.armada" | sudo tee -a /etc/hosts; \
		echo "DNS entry added.  Remember to remove it when done: sudo sed -i '' '/api.local.gitleaks.armada/d' /etc/hosts"; \
	else \
		echo "DNS entry already exists in /etc/hosts."; \
	fi

# Apply Kubernetes manifests
dev-apply:
	kubectl apply -f $(K8S_MANIFESTS)/namespace.yaml
	kubectl apply -f $(K8S_MANIFESTS)/config.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/rbac.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/kafka.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/api-gateway.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/api-ingress.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/controller.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/scanner.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/otel.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/prometheus.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/tempo.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/grafana.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/grafana-dashboards.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/grafana-dashboards-provisioning.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/loki.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/promtail.yaml -n $(NAMESPACE)

# Show status
dev-status:
	kubectl get pods -n $(NAMESPACE) -o wide
	@echo "\nLeader Election Status:"
	kubectl get lease -n $(NAMESPACE)

# Clean built binaries
clean:
	rm -f $(CONTROLLER_APP)
	rm -f $(SCANNER_APP)
	rm -f $(API_GATEWAY_APP)
	kubectl delete deployment kafka zookeeper -n $(NAMESPACE) || true
	kubectl delete -f $(K8S_MANIFESTS)/prometheus.yaml -n $(NAMESPACE) || true
	kubectl delete -f $(K8S_MANIFESTS)/grafana.yaml -n $(NAMESPACE) || true
	kubectl delete -f $(K8S_MANIFESTS)/postgres.yaml -n $(NAMESPACE) || true

# Additional convenience targets
dev: kind-up all

# Rebuild and redeploy without recreating cluster
redeploy: build-all docker-all kind-load dev-apply rollout-restart

rollout-restart: rollout-restart-controller rollout-restart-scanner rollout-restart-api-gateway

redeploy-%:
	$(MAKE) build-$* docker-$* kind-load-$*
	kubectl rollout restart deployment/$* -n $(NAMESPACE)

rollout-restart-controller:
	kubectl rollout restart deployment/controller -n $(NAMESPACE)

rollout-restart-scanner:
	kubectl rollout restart deployment/scanner -n $(NAMESPACE)

rollout-restart-api-gateway:
	kubectl rollout restart deployment/api-gateway -n $(NAMESPACE)

# View logs
logs-controller:
	kubectl logs -l app=controller -n $(NAMESPACE) --tail=100 -f

logs-scanner:
	kubectl logs -l app=scanner -n $(NAMESPACE) --tail=100 -f

# Scale deployments
scale-controller:
	kubectl scale deployment/controller -n $(NAMESPACE) --replicas=$(replicas)

scale-scanner:
	kubectl scale deployment/scanner -n $(NAMESPACE) --replicas=$(replicas)

# Proto targets
proto: proto-deps proto-gen

proto-deps:
	@if [ ! -f "$(PROTOC_GEN_GO)" ]; then \
		echo "Installing protoc-gen-go..."; \
			go install google.golang.org/protobuf/cmd/protoc-gen-go@latest; \
	fi

proto-gen:
	@for proto in $(PROTO_FILES); do \
		echo "Generating protobuf code for $$proto..."; \
		protoc --go_out=. --go_opt=paths=source_relative \
			--go_opt=M$$proto=github.com/ahrav/gitleaks-armada/proto \
			--proto_path=. \
			$$proto; \
	done

CONTROLLER_PARTITIONS := 3  # Matches controller replicas
SCANNER_PARTITIONS := 5     # Matches scanner replicas

# Kafka targets
kafka-setup:
	@echo "Pulling Kafka and Zookeeper images..."
	docker pull $(KAFKA_IMAGE)
	docker pull $(ZOOKEEPER_IMAGE)
	@echo "Loading images into kind cluster..."
	kind load docker-image $(KAFKA_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(ZOOKEEPER_IMAGE) --name $(KIND_CLUSTER)
	@echo "Applying Kafka manifests..."
	kubectl apply -f $(K8S_MANIFESTS)/kafka.yaml -n $(NAMESPACE)
	@echo "Waiting for pods to be ready..."
	sleep 10  # Give k8s time to create the pods
	kubectl wait --for=condition=ready pod -l app=zookeeper --timeout=120s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=kafka --timeout=120s -n $(NAMESPACE) || true
	@echo "Creating Kafka topics with partitions..."
	# Controller -> Scanner topics (use SCANNER_PARTITIONS)
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--create --if-not-exists \
		--topic $(KAFKA_ENUMERATION_TASK_TOPIC) \
		--bootstrap-server localhost:9092 \
		--partitions $(SCANNER_PARTITIONS) \
		--replication-factor 1
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--create --if-not-exists \
		--topic $(KAFKA_RULES_REQUEST_TOPIC) \
		--bootstrap-server localhost:9092 \
		--partitions $(SCANNER_PARTITIONS) \
		--replication-factor 1
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--create --if-not-exists \
		--topic $(KAFKA_HIGH_PRIORITY_TASK_TOPIC) \
		--bootstrap-server localhost:9092 \
		--partitions $(SCANNER_PARTITIONS) \
		--replication-factor 1
	# Scanner -> Controller topics (use CONTROLLER_PARTITIONS)
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--create --if-not-exists \
		--topic $(KAFKA_SCANNING_TASK_TOPIC) \
		--bootstrap-server localhost:9092 \
		--partitions $(CONTROLLER_PARTITIONS) \
		--replication-factor 1
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--create --if-not-exists \
		--topic $(KAFKA_RESULTS_TOPIC) \
		--bootstrap-server localhost:9092 \
		--partitions $(CONTROLLER_PARTITIONS) \
		--replication-factor 1
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--create --if-not-exists \
		--topic $(KAFKA_PROGRESS_TOPIC) \
		--bootstrap-server localhost:9092 \
		--partitions $(CONTROLLER_PARTITIONS) \
		--replication-factor 1
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--create --if-not-exists \
		--topic $(KAFKA_RULES_RESPONSE_TOPIC) \
		--bootstrap-server localhost:9092 \
		--partitions $(CONTROLLER_PARTITIONS) \
		--replication-factor 1
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--create --if-not-exists \
		--topic $(KAFKA_JOB_METRICS_TOPIC) \
		--bootstrap-server localhost:9092 \
		--partitions $(CONTROLLER_PARTITIONS) \
		--replication-factor 1

kafka-logs:
	@echo "Kafka logs:"
	kubectl logs -l app=kafka -n $(NAMESPACE) --tail=100 -f
	@echo "\nZookeeper logs:"
	kubectl logs -l app=zookeeper -n $(NAMESPACE) --tail=100 -f

kafka-topics:
	@echo "Listing topics and their configurations:"
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--list \
		--bootstrap-server localhost:9092
	@echo "\nTopic details:"
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--describe \
		--bootstrap-server localhost:9092

kafka-delete:
	kubectl delete deployment kafka zookeeper -n $(NAMESPACE) || true
	kubectl delete service kafka zookeeper -n $(NAMESPACE) || true

kafka-consumer-groups:
	@echo "Checking consumer group status..."
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-consumer-groups.sh \
		--bootstrap-server localhost:9092 \
		--describe \
		--all-groups

kafka-delete-topics:
	@echo "Deleting Kafka topics..."
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--bootstrap-server localhost:9092 \
		--delete \
		--topic $(KAFKA_ENUMERATION_TASK_TOPIC) || true
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--bootstrap-server localhost:9092 \
		--delete \
		--topic $(KAFKA_SCANNING_TASK_TOPIC) || true
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--bootstrap-server localhost:9092 \
		--delete \
		--topic $(KAFKA_RESULTS_TOPIC) || true
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--bootstrap-server localhost:9092 \
		--delete \
		--topic $(KAFKA_PROGRESS_TOPIC) || true
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--bootstrap-server localhost:9092 \
		--delete \
		--topic $(KAFKA_RULES_REQUEST_TOPIC) || true
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--bootstrap-server localhost:9092 \
		--delete \
		--topic $(KAFKA_RULES_RESPONSE_TOPIC) || true
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--bootstrap-server localhost:9092 \
		--delete \
		--topic $(KAFKA_HIGH_PRIORITY_TASK_TOPIC) || true
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--bootstrap-server localhost:9092 \
		--delete \
		--topic $(KAFKA_JOB_METRICS_TOPIC) || true

kafka-restart: kafka-delete
	@echo "Loading Kafka images..."
	kind load docker-image $(KAFKA_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(ZOOKEEPER_IMAGE) --name $(KIND_CLUSTER)
	@echo "Applying Kafka manifests..."
	kubectl apply -f k8s/kafka.yaml -n $(NAMESPACE)
	@echo "Waiting for pods to be ready..."
	sleep 10  # Give k8s more time to create the pods
	kubectl wait --for=condition=ready pod -l app=zookeeper --timeout=120s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=kafka --timeout=120s -n $(NAMESPACE) || true
	@echo "Creating Kafka topics..."
	$(MAKE) kafka-setup
	@echo "Kafka and Zookeeper restarted"

kafka-reset: kafka-delete-topics kafka-setup
	@echo "Kafka topics have been reset"

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
	docker pull $(TEMPO_IMAGE)
	docker pull $(LOKI)
	docker pull $(PROMTAIL)
	docker pull $(OTEL_COLLECTOR_IMAGE)
	kind load docker-image $(PROMETHEUS_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(GRAFANA_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(TEMPO_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(LOKI) --name $(KIND_CLUSTER)
	kind load docker-image $(PROMTAIL) --name $(KIND_CLUSTER)
	kind load docker-image $(OTEL_COLLECTOR_IMAGE) --name $(KIND_CLUSTER)
	kubectl apply -f $(K8S_MANIFESTS)/otel.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/prometheus.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/tempo.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/grafana.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/grafana-dashboards.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/grafana-dashboards-provisioning.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/loki.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/promtail.yaml -n $(NAMESPACE)
	@echo "Waiting for monitoring services to be ready..."
	kubectl wait --for=condition=ready pod -l app=otel-collector --timeout=120s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=prometheus --timeout=120s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=grafana --timeout=120s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=tempo --timeout=120s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=loki --timeout=120s -n $(NAMESPACE) || true
	kubectl wait --for=condition=ready pod -l app=promtail --timeout=120s -n $(NAMESPACE) || true
	@echo "Verifying Tempo connectivity..."
	kubectl run -n $(NAMESPACE) tempo-test --rm -i --restart=Never --image=busybox -- nc -zvw 1 tempo 4317 || true

monitoring-port-forward:
	@echo "Access Prometheus at http://localhost:9090"
	@echo "Access Grafana at http://localhost:3000 (admin/admin)"
	@echo "Access Tempo at http://localhost:3200"
	@echo "Access OpenTelemetry Collector at:"
	@echo "  - gRPC: localhost:4317"
	@echo "  - HTTP: localhost:4318"
	@echo "  - Prometheus: http://localhost:8889"
	@echo "  - zPages: http://localhost:55679"
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

# sqlc proto gen
sqlc-proto-gen:
	sqlc generate

# Add these new targets
postgres-port-forward:
	@echo "Port forwarding PostgreSQL..."
	kubectl port-forward -n $(NAMESPACE) svc/postgres 5432:5432 &

postgres-fix-dirty:
	@echo "Fixing dirty database state..."
	migrate -database "$(POSTGRES_URL)" -path db/migrations force 1

postgres-migrate-status:
	@echo "Checking migration status..."
	migrate -database "$(POSTGRES_URL)" -path db/migrations version

postgres-migrate-up:
	@echo "Running migrations..."
	migrate -database "$(POSTGRES_URL)" -path db/migrations up

postgres-migrate-down:
	@echo "Rolling back migrations..."
	migrate -database "$(POSTGRES_URL)" -path db/migrations down 1

# Use this to fix the dirty state and re-run migrations
postgres-migrate-fix: postgres-port-forward postgres-fix-dirty postgres-migrate-up
	@echo "Migration fix complete"

# Individual consumer group checks
kafka-debug-controller-consumers:
	@echo "Checking controller consumer group..."
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-consumer-groups.sh \
		--describe \
		--group controller \
		--bootstrap-server localhost:9092

kafka-debug-scanner-consumers:
	@echo "Checking scanner consumer group..."
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-consumer-groups.sh \
		--describe \
		--group scanner \
		--bootstrap-server localhost:9092

# Comprehensive Kafka debug target
kafka-debug: kafka-debug-controller-consumers kafka-debug-scanner-consumers
	@echo "\nChecking all topics..."
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
		--list \
		--bootstrap-server localhost:9092
	@echo "\nChecking all consumer groups..."
	kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-consumer-groups.sh \
		--describe \
		--all-groups \
		--bootstrap-server localhost:9092
	@echo "\nChecking topic details..."
	for topic in $(KAFKA_ENUMERATION_TASK_TOPIC) $(KAFKA_SCANNING_TASK_TOPIC) $(KAFKA_RESULTS_TOPIC) $(KAFKA_PROGRESS_TOPIC) $(KAFKA_RULES_REQUEST_TOPIC) $(KAFKA_RULES_RESPONSE_TOPIC) $(KAFKA_HIGH_PRIORITY_TASK_TOPIC) $(KAFKA_JOB_METRICS_TOPIC); do \
		echo "\nTopic: $$topic"; \
		kubectl exec -it -n $(NAMESPACE) deployment/kafka -- /opt/bitnami/kafka/bin/kafka-topics.sh \
			--describe \
			--topic $$topic \
			--bootstrap-server localhost:9092; \
	done

# Tempo-specific targets
tempo-logs:
	kubectl logs -l app=tempo -n $(NAMESPACE) --tail=100 -f

tempo-restart:
	kubectl rollout restart deployment/tempo -n $(NAMESPACE)

# Individual monitoring service restart targets
grafana-restart:
	kubectl rollout restart deployment/grafana -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/grafana-dashboards.yaml -n $(NAMESPACE)
	kubectl apply -f $(K8S_MANIFESTS)/grafana-dashboards-provisioning.yaml -n $(NAMESPACE)

prometheus-restart:
	kubectl rollout restart deployment/prometheus -n $(NAMESPACE)

loki-restart:
	kubectl rollout restart deployment/loki -n $(NAMESPACE)

promtail-restart:
	kubectl rollout restart deployment/promtail -n $(NAMESPACE)

# Restart all monitoring services
monitoring-restart: tempo-restart grafana-restart prometheus-restart otel-restart loki-restart promtail-restart

	@echo "All monitoring services restarted"

# Restart everything (monitoring + application)
restart-all: monitoring-restart rollout-restart
	@echo "All services restarted"

# Test targets
test:
	@echo "Running all tests..."
	go test -v -race -parallel=10 ./...

test-coverage:
	@echo "Running tests with coverage report..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated at coverage.html"

# Add new OpenTelemetry-specific targets
otel-logs:
	kubectl logs -l app=otel-collector -n $(NAMESPACE) --tail=100 -f

otel-restart:
	kubectl rollout restart deployment/otel-collector -n $(NAMESPACE)

# Add new targets for Loki and Promtail
loki-logs:
	kubectl logs -l app=loki -n $(NAMESPACE) --tail=100 -f

promtail-logs:
	kubectl logs -l app=promtail -n $(NAMESPACE) --tail=100 -f

# Port forwarding for development
api-gateway-port-forward:
	@echo "Port forwarding API Gateway to localhost:8080..."
	kubectl port-forward -n ingress-nginx svc/ingress-nginx-controller 8080:80
