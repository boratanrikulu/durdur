CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

.PHONY: generate compile build build-docker test test-docker

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./internal/generated...

compile:
	go build -o build/durdur ./cmd/durdur

build: generate compile

build-docker:
	docker build -t durdur -f images/Dockerfile .

test:
	go test ./... -v -cover -race

test-docker:
	docker build -t durdur-test -q -f images/Dockerfile.tests . && \
	docker run --rm durdur-test
