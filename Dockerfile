# Build stage
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/securecore ./cmd/gateway

# Runtime stage — minimal, no interpreter or package manager
FROM scratch
COPY --from=build /out/securecore /securecore
COPY config.yaml /config.yaml
EXPOSE 8080
ENTRYPOINT ["/securecore", "--config", "/config.yaml"]
