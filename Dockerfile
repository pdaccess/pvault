FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN GOTOOLCHAIN=auto go mod download

COPY . .

RUN GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w -X 'main.Commit=${COMMIT_TXT}' -X 'main.BuildTime=${BUILD_DATE}' -X 'main.BuildEnv=${BUILD_ENV}'" -o pvault ./cmd

FROM alpine:3.19

ENV USER=pdaccess
ENV GROUPNAME=$USER
ENV UID=10001
ENV GID=10001

RUN addgroup \
    --gid "$GID" \
    "$GROUPNAME" \
&&  adduser \
    --disabled-password \
    --gecos "" \
    --home "$(pwd)" \
    --ingroup "$GROUPNAME" \
    --no-create-home \
    --uid "$UID" \
    $USER

WORKDIR /app

RUN apk add --no-cache libc6-compat gcompat ca-certificates

USER pdaccess:pdaccess

COPY --from=builder /app/pvault /app/pvault

EXPOSE 50051

ENTRYPOINT ["/app/pvault"]