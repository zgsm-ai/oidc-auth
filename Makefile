# Makefile for OIDC Authentication Server

# Variables
APP_NAME := oidc-auth
IMAGE_NAME := zgsm-ai/oidc-auth
HELM_CHART := ./charts/oidc-auth
PORT := 8080
CONFIG_FILE := config/config.yaml

.DEFAULT_GOAL := help

# Help target
.PHONY: help
help: ## Show this help
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development targets
.PHONY: dev
dev: ## Run the application in development mode
	@echo "Starting development server..."
	go run cmd/main.go serve --config $(CONFIG_FILE)

.PHONY: build
build: ## Build the Go binary
	@echo "Building binary..."
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o bin/$(APP_NAME) cmd/main.go

.PHONY: test
test: ## Run tests
	@echo "Running tests..."
	go test -v ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

.PHONY: fmt
fmt: ## Format Go code
	@echo "Formatting code..."
	go fmt ./...

.PHONY: lint
lint: ## Run linter
	@echo "Running linter..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not found, installing..."; go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; }
	golangci-lint run

.PHONY: mod
mod: ## Download and tidy Go modules
	@echo "Tidying Go modules..."
	go mod download
	go mod tidy

# Docker targets
.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(IMAGE_NAME) .

.PHONY: docker-run
docker-run: ## Run Docker container
	@echo "Running Docker container..."
	docker run -d \
		--name $(APP_NAME) \
		-p $(PORT):$(PORT) \
		-v $(PWD)/config:/app/config \
		-e DATABASE_PASSWORD=your_password \
		-e AUTH_CLIENT_SECRET=your_secret \
		$(IMAGE_NAME)

.PHONY: docker-stop
docker-stop: ## Stop Docker container
	@echo "Stopping Docker container..."
	-docker stop $(APP_NAME)
	-docker rm $(APP_NAME)

.PHONY: docker-logs
docker-logs: ## Show Docker container logs
	docker logs -f $(APP_NAME)

.PHONY: docker-clean
docker-clean: ## Clean Docker images and containers
	@echo "Cleaning Docker images and containers..."
	-docker stop $(APP_NAME)
	-docker rm $(APP_NAME)
	-docker rmi $(IMAGE_NAME)

# Kubernetes/Helm targets
.PHONY: helm-package
helm-package: ## Package Helm chart
	@echo "Packaging Helm chart..."
	@mkdir -p charts
	helm package $(HELM_CHART) --destination charts --version 1.0.0 --app-version 1.0.0

.PHONY: helm-install
helm-install: ## Install Helm chart
	@echo "Installing Helm chart..."
	helm install -n zgsm $(APP_NAME) ./charts/$(APP_NAME)-1.0.0.tgz --create-namespace

.PHONY: helm-upgrade
helm-upgrade: ## Upgrade Helm chart
	@echo "Upgrading Helm chart..."
	helm upgrade -n zgsm $(APP_NAME) ./charts/$(APP_NAME)-1.0.0.tgz

.PHONY: helm-uninstall
helm-uninstall: ## Uninstall Helm chart
	@echo "Uninstalling Helm chart..."
	helm uninstall -n zgsm $(APP_NAME)

# Deployment targets
.PHONY: deploy
deploy: docker-build helm-package helm-install ## Build and deploy the application

.PHONY: redeploy
redeploy: docker-build helm-package helm-upgrade ## Rebuild and redeploy the application

# Cleanup targets
.PHONY: clean
clean: docker-clean ## Clean all build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -rf charts/$(APP_NAME)-*.tgz
	rm -f coverage.out coverage.html

# Setup development environment
.PHONY: setup
setup: ## Setup development environment
	@echo "Setting up development environment..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	@[ -f config/config.yaml ] || cp config/config.yaml.example config/config.yaml
	@echo "Development environment setup complete!"
	@echo "Please edit config/config.yaml with your settings"

# Health check
.PHONY: health
health: ## Check application health
	@echo "Checking application health..."
	@curl -f http://localhost:$(PORT)/health > /dev/null 2>&1 && echo "✅ Application is healthy" || echo "❌ Application is not responding" 