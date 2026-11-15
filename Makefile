.PHONY: build run test race bench vet clean

BINARY := securecore

build:
	go build -ldflags "-s -w" -o $(BINARY) ./cmd/gateway

run:
	go run ./cmd/gateway --config config.yaml

test:
	go test ./...

# Requires CGO and a C compiler (CGO_ENABLED=1).
race:
	go test -race ./...

bench:
	go run ./cmd/bench -duration 5s -concurrency 50
	go test -bench=. -benchmem -run=^$$ ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY) $(BINARY).exe
