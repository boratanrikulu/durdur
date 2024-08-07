CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
TNAMES ?= .*

.PHONY: generate compile build build-docker test test-docker

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./internal/generated...

compile:
	CGO_ENABLED=0 go build -o build/durdur ./cmd/durdur

build: generate compile

build-docker:
	docker build -t durdur -f images/Dockerfile .

# To run all tests, just run `make test`.
# If you need to run specific tests, you can use `TNAMES`,
# Example: `TNAMES="TestDrop|TestUndrop" make test`
test: generate
	CGO_ENABLED=0 go test -exec sudo ./... -run "^$(TNAMES)$\" -v -cover -coverprofile=coverage.txt -covermode=atomic -p=1

test-docker:
	docker build -t durdur-test -q -f images/Dockerfile.tests . && \
	docker run --rm --privileged -v /sys/fs/bpf:/sys/fs/bpf durdur-test
