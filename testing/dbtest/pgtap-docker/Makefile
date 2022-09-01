REGISTRY_NAME ?= docker.io/hashicorpboundary
TEST_IMAGE_NAME = pgtap
PG_VERSION ?= 13

# Before running this target a builder instance needs to be setup, ie:
#  docker buildx create --driver docker-container --use
.PHONY: docker-build
docker-build:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t $(REGISTRY_NAME)/$(TEST_IMAGE_NAME):$(PG_VERSION) \
		--build-arg PG_VERSION=$(PG_VERSION) \
		-f Dockerfile .

.PHONY: docker-load
docker-load:
	docker buildx build \
		--load \
		-t $(REGISTRY_NAME)/$(TEST_IMAGE_NAME):$(PG_VERSION) \
		--build-arg PG_VERSION=$(PG_VERSION) \
		-f Dockerfile .
