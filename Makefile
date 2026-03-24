.PHONY: build run migrate seed test test-race vet clean clipagent precheck

# Build
build:
	go build -o bin/docvault ./cmd/server

clipagent:
	GOOS=windows GOARCH=amd64 go build -o bin/docvault-clip.exe ./cmd/clipagent

# Run
run: build
	./bin/docvault serve

# Database
migrate: build
	./bin/docvault migrate

seed: build
	./bin/docvault seed

# Test
test:
	go test ./...

test-race:
	go test -race ./...

test-v:
	go test -v ./...

# Quality
vet:
	go vet ./...

# Pre-deployment verification (RUN THIS BEFORE EVERY DEPLOY)
precheck:
	@bash scripts/precheck.sh

# Clean
clean:
	rm -rf bin/
