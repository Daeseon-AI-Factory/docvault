.PHONY: build run migrate seed test test-race vet clean clipagent sign-windows precheck test-all ci

# Build
build:
	go build -o bin/docvault ./cmd/server

clipagent:
	GOOS=windows GOARCH=amd64 go build -o bin/docvault-clip.exe ./cmd/clipagent

sign-windows: clipagent
	@if [ -z "$$DOCVAULT_WINDOWS_CERT_PATH" ] || [ -z "$$DOCVAULT_WINDOWS_CERT_PASSWORD" ]; then \
		echo "Set DOCVAULT_WINDOWS_CERT_PATH and DOCVAULT_WINDOWS_CERT_PASSWORD before signing."; \
		exit 1; \
	fi
	@echo "Sign bin/docvault-clip.exe on a Windows runner with signtool.exe."
	@echo "Example:"
	@echo "  signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f %DOCVAULT_WINDOWS_CERT_PATH% /p <redacted> bin\\docvault-clip.exe"

clipagent-mac:
	GOOS=darwin GOARCH=amd64 go build -o bin/docvault-clip-mac ./cmd/clipagent

clipagent-mac-arm:
	GOOS=darwin GOARCH=arm64 go build -o bin/docvault-clip-mac-arm64 ./cmd/clipagent

clipagent-all: clipagent clipagent-mac clipagent-mac-arm

# Run
run: build
	./bin/docvault serve

# Database
migrate: build
	./bin/docvault migrate

seed: build
	./bin/docvault seed

# Test individual packages (avoids Windows memory issues)
test-all:
	@echo "=== Building ==="
	go build ./...
	@echo "=== Vet ==="
	go vet ./...
	@echo "=== Testing config ==="
	go test -count=1 ./internal/config/
	@echo "=== Testing auth ==="
	go test -count=1 ./internal/auth/
	@echo "=== Testing user ==="
	go test -count=1 ./internal/user/
	@echo "=== Testing vault ==="
	go test -count=1 ./internal/vault/
	@echo "=== Testing audit ==="
	go test -count=1 ./internal/audit/
	@echo "=== Testing alert ==="
	go test -count=1 ./internal/alert/
	@echo "=== Testing endpoint ==="
	go test -count=1 ./internal/endpoint/
	@echo "=== Testing web ==="
	go test -count=1 ./internal/web/
	@echo ""
	@echo "ALL TESTS PASSED"

# Quick test (parallel, may OOM on low-memory machines)
test:
	go test ./...

test-race:
	go test -race ./...

test-v:
	go test -v ./...

# Quality
vet:
	go vet ./...

# CI: full check (build + vet + all tests)
ci: test-all
	@echo "CI check passed"

# Pre-deployment verification (RUN THIS BEFORE EVERY DEPLOY)
precheck:
	@bash scripts/precheck.sh

# Clean
clean:
	rm -rf bin/
