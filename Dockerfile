FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN GOTOOLCHAIN=auto go mod download

COPY . .

RUN GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w -X 'main.Commit=${COMMIT_TXT}' -X 'main.BuildTime=${BUILD_DATE}' -X 'main.BuildEnv=${BUILD_ENV}'" -o pvault ./cmd

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/pvault .

EXPOSE 50051

ENTRYPOINT ["./pvault"]