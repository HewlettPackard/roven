.ONESHELL:

EKS_DIR ?= ./dev/kubernetes
BINARIES ?= hybrid_server hybrid_agent

OSES ?= linux windows
ARCHITECTURES ?= amd64 arm64
VERSION ?= latest-local
DOCKER_HUB ?= ${DOCKER_HUB}

BUILD_DIR ?= ./build
PLATFORM_LINUX ?= $(foreach os, $(OSES), $(foreach architecture, $(ARCHITECTURES), $(if $(findstring linux, $(os)), --platform $(os)/$(architecture))))
BUILD_TARGETS := $(foreach binary, $(BINARIES), $(foreach os, $(OSES), $(foreach architecture, $(ARCHITECTURES), $(binary)-$(os)-$(architecture))))
DOCKER_TARGETS := $(foreach binary, $(BINARIES), $(binary)-docker)

target_words = $(subst -, ,$@)
target_binary = $(word 1, $(target_words))
target_binary_unified = $(subst _,,$(word 1, $(target_words)))
target_os = $(word 2, $(target_words))
target_architecture = $(word 3, $(target_words))
target_software_type = $(word 2, $(subst _, ,$(target_binary)))

target_binary_hyphens = $(subst _,-attestor-,$(target_binary))

build: $(BUILD_TARGETS)
$(BUILD_TARGETS):
	CGO_ENABLED=0 GOOS=$(target_os) GOARCH=$(target_architecture) go build -ldflags="-s -w -extldflags -static" -o $(BUILD_DIR)/$(target_os)/$(target_architecture)/$(target_binary_unified) cmd/$(target_binary)/main.go

test: test-unit test-integration
	go test ./...

test-unit:
	go test ./...

test-unit-race:
	go test -race ./...

test-integration:
	bash ./test/integration/test.sh

docker-linux: $(DOCKER_TARGETS)
$(DOCKER_TARGETS):
	docker build -f ./dev/docker/$(target_software_type).Dockerfile $(PLATFORM_LINUX) --build-arg BINARY=$(target_binary_unified) -t $(DOCKER_HUB)/$(target_binary_hyphens):$(VERSION) .
	docker push $(DOCKER_HUB)/$(target_binary_hyphens):$(VERSION)

deploy-spire-eks:
	kubectl delete --all daemonsets.app --namespace=spire
	kubectl delete --all statefulset.app --namespace=spire
	kubectl delete --ignore-not-found namespace spire
	envsubst < $(EKS_DIR)/server.yaml | kubectl apply -f -
	envsubst < $(EKS_DIR)/agent.yaml | kubectl apply -f -

clean:
	rm -rf $(BUILD_DIR)

.PHONY: $(BUILD_TARGETS) $(DOCKER_TARGETS) build test docker clean
