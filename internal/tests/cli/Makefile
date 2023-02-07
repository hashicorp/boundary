all: test

REGISTRY_NAME ?= docker.io/hashicorp
TEST_VAULT_IMAGE_NAME=vault
TEST_VAULT_IMAGE ?= $(REGISTRY_NAME)/$(TEST_VAULT_IMAGE_NAME):1.12.2
TEST_VAULT_PORT ?= 8200
TEST_VAULT_CONTAINER_NAME ?= boundary-cli-tests-vault

VAULT_ADDR ?= "http://127.0.0.1:$(TEST_VAULT_PORT)"
VAULT_TOKEN ?= boundarytok

.PHONY: test-vault-up
test-vault-up:
	@echo "Using image: $(TEST_VAULT_IMAGE)"
	@echo " vault addr: $(VAULT_ADDR)"
	@echo "vault token: $(VAULT_TOKEN)"
	@docker run \
		-d \
		--name $(TEST_VAULT_CONTAINER_NAME) \
		-e VAULT_DEV_ROOT_TOKEN_ID=$(VAULT_TOKEN) \
		-p $(TEST_VAULT_PORT):8200 \
		--cap-add IPC_LOCK \
		$(TEST_VAULT_IMAGE)
	@echo "Container name: $(TEST_VAULT_CONTAINER_NAME)"
	@echo "Test vault available at: $(VAULT_ADDR)"
	@echo "For vault logs run:"
	@echo "    docker logs $(TEST_VAULT_CONTAINER_NAME)"

.PHONY: test-vault-down
test-vault-down:
	docker stop $(TEST_VAULT_CONTAINER_NAME) || true
	docker rm -v $(TEST_VAULT_CONTAINER_NAME) || true

.PHONY: test
test:
	./test.sh
