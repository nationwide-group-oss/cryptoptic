# Local equivalents of the commands the GitHub Action exposes.
# Every target runs in the same container CI and consumers use.

IMAGE ?= cryptoptic
WORKSPACE ?= $(CURDIR)
DOCKER_RUN = docker run --rm --volume "$(WORKSPACE):/workspace"

.DEFAULT_GOAL := help
.PHONY: help build lint python-tests query-suite scan shell clean

help: ## Show this help
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-14s %s\n", $$1, $$2}'

build: ## Build the container image
	docker build --tag $(IMAGE) .

lint: ## Lint the entrypoint and Dockerfile
	shellcheck --shell=bash entrypoint.sh
	docker run --rm --interactive hadolint/hadolint \
		hadolint - < Dockerfile

python-tests: build ## Run the Python test suite in the image
	docker run --rm $(IMAGE) python-tests

query-suite: build ## Run the JavaScript CodeQL query suite; SARIF lands in ./output
	$(DOCKER_RUN) $(IMAGE) test

scan: build ## Run a scan; set GH_TOKEN, and ORG or REPO, and TARGET_LANG
	$(DOCKER_RUN) \
		--env GH_TOKEN --env ORG --env REPO --env TARGET_LANG \
		$(IMAGE) scan

shell: build ## Open a shell in the image for debugging
	docker run --rm --interactive --tty --entrypoint bash \
		--volume "$(WORKSPACE):/workspace" $(IMAGE)

clean: ## Remove local build and result artefacts
	rm -rf org-sarif output cbom-test-db
	-docker image rm $(IMAGE)
