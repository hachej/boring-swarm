# Multi-stage build for bsw (boring-swarm process manager)
# Stage 1: Build the Go binary
FROM golang:1.24-alpine AS builder

WORKDIR /build
COPY cli/bsw/ ./
RUN go build -ldflags="-s -w" -o /bsw .

# Stage 2: Runtime image
# Using alpine (not scratch) because bsw shells out to tmux, git, and provider CLIs
FROM alpine:3.21

RUN apk add --no-cache \
    tmux \
    git \
    bash \
    curl \
    ca-certificates

COPY --from=builder /bsw /usr/local/bin/bsw

# Default persona and prompt directories
RUN mkdir -p /workspace/personas/prompts

WORKDIR /workspace

# Configurable timeouts via env vars
ENV BSW_STALE_TIMEOUT_SEC=600
ENV BSW_DOCTOR_TIMEOUT_SEC=15
ENV BSW_REVIEW_TIMEOUT_SEC=90

ENTRYPOINT ["bsw"]
CMD ["doctor"]
