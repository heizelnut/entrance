.PHONY: build test vet lint dev dev-agent clean cross-linux

BIN_DIR ?= bin
TOKEN ?= local-dev

build:
	go build -o $(BIN_DIR)/entrance ./cmd/entrance
	go build -o $(BIN_DIR)/entranced ./cmd/entranced

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

# dev: bastion on http://localhost:8443 (plain HTTP on localhost is a secure
# context, so WebAuthn works without a trusted certificate). Ctrl-C to stop.
dev:
	go build -o $(BIN_DIR)/entrance ./cmd/entrance
	@echo "bastion: http://localhost:8443  (bootstrap token: $(TOKEN))"
	./$(BIN_DIR)/entrance --dev --listen 127.0.0.1:8443 --hostname localhost \
		--token $(TOKEN) --data-dir ./data

# dev-agent: an agent that connects to the local dev bastion.
dev-agent:
	go build -o $(BIN_DIR)/entranced ./cmd/entranced
	./$(BIN_DIR)/entranced --server http://127.0.0.1:8443 --token $(TOKEN) \
		--hostname dev-host --audit-log ./data/agent-audit.log

cross-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/linux-amd64/entrance ./cmd/entrance
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/linux-amd64/entranced ./cmd/entranced
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(BIN_DIR)/linux-arm64/entrance ./cmd/entrance
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(BIN_DIR)/linux-arm64/entranced ./cmd/entranced
	@echo "linux binaries in $(BIN_DIR)/linux-{amd64,arm64}/"

clean:
	rm -rf $(BIN_DIR) data
