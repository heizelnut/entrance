.PHONY: build test lint vet e2e dev clean cross-linux

BIN_DIR ?= bin

build:
	go build -o $(BIN_DIR)/entrance ./cmd/entrance
	go build -o $(BIN_DIR)/entranced ./cmd/entranced
	go build -o $(BIN_DIR)/entrui ./cmd/entrui

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

# e2e runs the full rootless vertical slice: real entrance + entranced
# binaries over HTTPS, WG handshake inside the control channel, relay echo,
# revocation. Requires no root.
e2e:
	go test ./tests/e2e/ -v -timeout 180s

# Real TUN end-to-end on this machine (requires sudo: utun interfaces + ifconfig).
e2e-tun:
	sudo ./scripts/e2e-tun.sh

# Local smoke: dev bastion on :8443. Ctrl-C to stop.
dev:
	go build -o $(BIN_DIR)/entrance ./cmd/entrance
	@echo "started dev control plane: https://127.0.0.1:8443 (self-signed; pin with --ca-file)"
	ENTRANCE_ADMIN_PASSWORD=local-dev ./$(BIN_DIR)/entrance serve --dev \
		--data-dir ./data/dev --listen 127.0.0.1:8443

cross-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/linux-amd64/entrance ./cmd/entrance
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/linux-amd64/entranced ./cmd/entranced
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(BIN_DIR)/linux-arm64/entrance ./cmd/entrance
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(BIN_DIR)/linux-arm64/entranced ./cmd/entranced
	@echo "linux binaries in $(BIN_DIR)/linux-{amd64,arm64}/"

clean:
	rm -rf $(BIN_DIR) data