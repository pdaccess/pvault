.PHONY: build run test unit-tests

LINUX_AMD64 := GOOS=linux GOARCH=amd64
GIT_BRANCH := $(shell git rev-parse  --abbrev-ref HEAD)
GIT_COMMIT := $(shell git rev-parse --short HEAD)
COMMIT_TXT := ${GIT_BRANCH}/${GIT_COMMIT}
BUILD_DATE := $(shell date)
BUILD_ENV := $(shell uname -a)

build:
	go build -o bin/pvault ./cmd

run:
	go run ./cmd

test:
	go test ./... -v -count=1

unit-tests:
	go test -cover ./...

generate:
	protoc --go_out=pkg/ --go_opt=paths=source_relative \
    --go-grpc_out=pkg/ --go-grpc_opt=paths=source_relative \
    api/v1/pvault.proto

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/

# Docker Compose
docker-up:
	docker-compose up --build

docker-down:
	docker-compose down -v

docker-build:
	docker-compose build

docker-logs:
	docker-compose logs -f

docker-ps:
	docker-compose ps

# Local development with Docker Compose
start: docker-up
	@echo "Waiting for services..."
	@sleep 10
	@echo "Services ready! Use 'make login' to login, then 'make list-vaults' etc."


ci-build: cmd/main.go
	docker build --no-cache --build-arg COMMIT_TXT="${COMMIT_TXT}" --build-arg BUILD_DATE="${BUILD_DATE}" --build-arg BUILD_ENV="${BUILD_ENV}" -t ghcr.io/pdaccess/pvault:${GIT_COMMIT} -f Dockerfile .

ci-push:
	docker push ghcr.io/pdaccess/pvault:${GIT_COMMIT}
	docker tag ghcr.io/pdaccess/pvault:${GIT_COMMIT} ghcr.io/pdaccess/pvault:latest
	docker push ghcr.io/pdaccess/pvault:latest

stop: docker-down

# Auth - login to Keycloak and store token
login:
	go run ./cmd login --keycloak http://localhost:8180 --client-id pvault-client

logout:
	go run ./cmd logout

# Connect commands (auto-loads token from ~/.pvault/token)
list-vaults:
	go run ./cmd list-vaults

create-vault:
	go run ./cmd create-vault --vault-id "d4e1efc2-cf10-4ffd-b35d-69e1f02afa8f"

protect-secret:
	go run ./cmd protect-secret --secret-id "583024bc-f923-44d9-b1ec-4476e8d147d9" --vault-id "d4e1efc2-cf10-4ffd-b35d-69e1f02afa8f" --plaintext "my-secret 2"

uncover-secret:
	go run ./cmd uncover-secret --secret-id "583024bc-f923-44d9-b1ec-4476e8d147d9" --action see

update-capabilities:
	go run ./cmd update-secret-capabilities --secret-id "583024bc-f923-44d9-b1ec-4476e8d147d9" --user-id "b2c5011a-5265-4007-ab23-0d0f5191619b" --capabilities "see,write"

audit-logs:
	go run ./cmd get-audit-logs --start 0 --limit 10
