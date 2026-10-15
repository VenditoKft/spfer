.DEFAULT_GOAL := help

REMOTE ?= origin
BRANCH ?= main

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: test
test: ## Run tests
	go test ./...

.PHONY: race
race: ## Run tests with the race detector
	go test -race ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: fmt
fmt: ## Check formatting (fails if any file needs gofmt)
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "needs gofmt:"; echo "$$out"; exit 1; fi

.PHONY: cover
cover: ## Run tests and open an HTML coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

.PHONY: check
check: fmt vet race ## Run everything CI runs (fmt, vet, race tests)

.PHONY: version
version: ## Show the latest version, commits since, and the proposed next version
	@scripts/version.sh

# Usage:
#   make release              tag the proposed version
#   make release BUMP=minor   force a major/minor/patch bump
#   make release VERSION=v1.2.3
.PHONY: release
release: ## Tag and push a new version (BUMP=major|minor|patch or VERSION=vX.Y.Z)
	@test -z "$$(git status --porcelain)" || { echo "working tree is not clean"; exit 1; }
	@test "$$(git rev-parse --abbrev-ref HEAD)" = "$(BRANCH)" || { echo "not on $(BRANCH)"; exit 1; }
	@git fetch --quiet --tags $(REMOTE) $(BRANCH)
	@test "$$(git rev-parse HEAD)" = "$$(git rev-parse $(REMOTE)/$(BRANCH))" || { echo "$(BRANCH) is not in sync with $(REMOTE)/$(BRANCH)"; exit 1; }
	@$(MAKE) --no-print-directory check
	@scripts/version.sh
	@version="$(VERSION)"; \
	if [ -z "$$version" ]; then version="$$(scripts/version.sh --next $(BUMP))" || exit 1; fi; \
	echo "$$version" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' || { echo "invalid version: $$version"; exit 1; }; \
	if git rev-parse -q --verify "refs/tags/$$version" >/dev/null; then echo "tag $$version already exists"; exit 1; fi; \
	echo; printf "Tag and push %s to $(REMOTE)? [y/N] " "$$version"; read ans; \
	[ "$$ans" = "y" ] || [ "$$ans" = "Y" ] || { echo "aborted"; exit 1; }; \
	git tag -a "$$version" -m "Release $$version" && \
	git push $(REMOTE) "$$version" && \
	echo "Released $$version"
