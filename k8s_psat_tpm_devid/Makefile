.ONESHELL:

BINARIES ?= devid_psat_attestor_server devid_psat_attestor_agent
OSES ?= linux
ARCHITECTURES ?= amd64 arm64
VERSION ?= develop
DOCKER_REGISTRY ?= docker.io
DOCKER_REPOSITORY_PREFIX ?= myhub
BUILD_DIR ?= ./build
PLATFORMS ?= $(foreach os, $(OSES), $(foreach architecture, $(ARCHITECTURES), --platform $(os)/$(architecture)))

BUILD_TARGETS := $(foreach binary, $(BINARIES), $(foreach os, $(OSES), $(foreach architecture, $(ARCHITECTURES), $(binary)-$(os)-$(architecture))))
DOCKER_TARGETS := $(foreach binary, $(BINARIES), $(binary)-docker)

target_words = $(subst -, ,$@)
target_binary = $(word 1, $(target_words))
target_os = $(word 2, $(target_words))
target_architecture = $(word 3, $(target_words))

target_binary_hyphens = $(subst _,-,$(target_binary))

build: $(BUILD_TARGETS)
$(BUILD_TARGETS):
	CGO_ENABLED=0 GOOS=$(target_os) GOARCH=$(target_architecture) go build -ldflags="-s -w -extldflags -static" -o $(BUILD_DIR)/$(target_os)/$(target_architecture)/$(target_binary) cmd/$(target_binary)/main.go

test: test-unit test-integration
	go test ./...

test-unit:
	go test ./...

test-integration:
	bash ./test/integration/run.sh

docker: $(DOCKER_TARGETS)
$(DOCKER_TARGETS):
	docker build -f ./dev/docker/Dockerfile $(PLATFORMS) --build-arg BINARY=$(target_binary) -t $(DOCKER_REGISTRY)/$(DOCKER_REPOSITORY_PREFIX)/$(target_binary_hyphens):$(VERSION) .
	docker push $(DOCKER_REGISTRY)/$(DOCKER_REPOSITORY_PREFIX)/$(target_binary_hyphens):$(VERSION)

docker-build:
	CGO_ENABLED=0 GOOS=$(TARGETOS) GOARCH=$(TARGETARCH) go build -ldflags="-s -w -extldflags -static" -o ${BINARY} cmd/${BINARY}/main.go

clean:
	rm -rf $(BUILD_DIR)

.PHONY: $(BUILD_TARGETS) $(DOCKER_TARGETS) build test docker clean
