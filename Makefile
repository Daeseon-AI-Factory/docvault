.PHONY: build run migrate seed test test-race vet clean clipagent sign-windows precheck test-all ci

# Build
build:
	go build -o bin/docvault ./cmd/server

clipagent:
	GOOS=windows GOARCH=amd64 go build -o bin/docvault-clip.exe ./cmd/clipagent

# Sign the Windows agent with an Authenticode code-signing cert (.pfx/.p12).
# Cross-platform via osslsigncode (brew install osslsigncode) so it runs on the Mac.
# Output: bin/dvclip-windows-amd64-signed.exe — deploy that to the box's
# /vault/agents/dvclip-windows-amd64.exe. See docs/CODE_SIGNING.md.
# A real, trusted cert is what removes the SmartScreen warning; without one the
# binary stays unsigned and SmartScreen will warn. This target only signs — it
# cannot conjure a certificate.
sign-windows: clipagent
	@if [ -z "$$DOCVAULT_WINDOWS_CERT_PATH" ] || [ -z "$$DOCVAULT_WINDOWS_CERT_PASSWORD" ]; then \
		echo "Set DOCVAULT_WINDOWS_CERT_PATH (.pfx) and DOCVAULT_WINDOWS_CERT_PASSWORD first. See docs/CODE_SIGNING.md"; \
		exit 1; \
	fi
	@command -v osslsigncode >/dev/null 2>&1 || { echo "osslsigncode not found — install it: brew install osslsigncode"; exit 1; }
	osslsigncode sign \
		-pkcs12 "$$DOCVAULT_WINDOWS_CERT_PATH" -pass "$$DOCVAULT_WINDOWS_CERT_PASSWORD" \
		-n "DocVault Clipboard Agent" -i "https://docvault.daeseon.ai" \
		-ts "http://timestamp.digicert.com" \
		-in bin/docvault-clip.exe -out bin/dvclip-windows-amd64-signed.exe
	osslsigncode verify bin/dvclip-windows-amd64-signed.exe
	@echo "Signed -> bin/dvclip-windows-amd64-signed.exe"
	@echo "Deploy: copy it to the box as /vault/agents/dvclip-windows-amd64.exe (see docs/CODE_SIGNING.md)."

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
