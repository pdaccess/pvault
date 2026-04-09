.PHONY: build run test unit-tests

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
	go run ./cmd protect-secret --secret-id "583024bc-f923-44d9-b1ec-4476e8d147d9" --vault-id "d4e1efc2-cf10-4ffd-b35d-69e1f02afa8f" --plaintext "my-secret"

uncover-secret:
	go run ./cmd uncover-secret --secret-id "583024bc-f923-44d9-b1ec-4476e8d147d9" --action see
