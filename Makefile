.PHONY: build build-mcponly build-all vet fmt-check lint test test-conformance test-race tidy-check generate generate-check check-gates check-gates-selftest verify docker-image docker-smoke vet-cross release-check release-lint release-install-check vet-tags spec-lint cats-run cats-selftest pen-check pen-selftest
export CGO_ENABLED=0
PKGS_UNIT = $$(go list ./... | grep -v '^github.com/ericfitz/agentmesh/internal/conformance')

build:       ## Build the agentmesh binary (no cgo), as the release build will
	go build -trimpath -o agentmesh .
build-mcponly: ## Build the agentmesh-mcponly binary (no cgo; the MCP-only client)
	go build -trimpath -o agentmesh-mcponly ./cmd/agentmesh-mcponly
build-all:   ## Compile every package
	go build ./...
vet:
	go vet ./...
fmt-check:   ## gofmt over this module's Go files (files, never directories: gofmt recurses into a directory argument)
	@out=$$(gofmt -l $$(go list -f '{{range .GoFiles}}{{$$.Dir}}/{{.}} {{end}}{{range .TestGoFiles}}{{$$.Dir}}/{{.}} {{end}}{{range .XTestGoFiles}}{{$$.Dir}}/{{.}} {{end}}' ./...)); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
lint:        ## golangci-lint v2 default linters (no .golangci.yml)
	golangci-lint run ./...
test:        ## Unit tests: every package except internal/conformance (no Docker needed)
	go test $(PKGS_UNIT)
test-race:   ## Every package under the race detector, suites included (needs Postgres like verify)
	go test -race -count=1 ./...
tidy-check:  ## go.mod and go.sum are tidy (part of verify; also a step of the dispatch-only ci.yml)
	go mod tidy -diff
generate:    ## Regenerate internal/gen from api/openapi.yaml with the pinned oapi-codegen
	go tool oapi-codegen -config api/oapi-codegen.yaml api/openapi.yaml
	go tool oapi-codegen -config api/oapi-codegen-spec.yaml api/openapi.yaml
generate-check: generate  ## Fail when internal/gen is not exactly what api/ generates (modified, staged, deleted or untracked files after regeneration)
	@dirty=$$(git status --porcelain --untracked-files=all -- internal/gen); if [ -n "$$dirty" ]; then echo "internal/gen is stale or polluted (run make generate, then commit or remove):"; echo "$$dirty"; git --no-pager diff --stat -- internal/gen; exit 1; fi
VACUUM_MIN_VERSION := 0.36.2
VACUUM ?= vacuum

spec-lint:   ## vacuum lint of api/openapi.yaml with api/vacuum-ruleset.yaml at fail-severity info (part of verify; needs vacuum $(VACUUM_MIN_VERSION) or newer)
	@command -v $(VACUUM) >/dev/null 2>&1 || { echo "spec-lint: vacuum is not installed; run: go install github.com/daveshanley/vacuum@v$(VACUUM_MIN_VERSION) (or brew install vacuum; $(VACUUM_MIN_VERSION) or newer)"; exit 1; }
	@v="$$($(VACUUM) version 2>/dev/null | tr -d '[:space:]' | sed 's/^v//')"; awk -v have="$$v" -v want="$(VACUUM_MIN_VERSION)" 'BEGIN { nh = split(have, h, "."); split(want, w, "."); if (nh < 3 || have !~ /^[0-9]+\.[0-9]+\.[0-9]+$$/) exit 1; for (i = 1; i <= 3; i++) { if (h[i] + 0 > w[i] + 0) exit 0; if (h[i] + 0 < w[i] + 0) exit 1 } exit 0 }' || { echo "spec-lint: vacuum $$v installed, want $(VACUUM_MIN_VERSION) or newer"; exit 1; }
	$(VACUUM) lint -r api/vacuum-ruleset.yaml -n info -d -q -b --no-clip api/openapi.yaml
test-conformance:  ## Store and Bus conformance suites on SQLite and Postgres; -count=1 so an unreachable Postgres can never be masked by the test cache
	go test -count=1 -p 1 ./internal/conformance/...
	@# the bus suite runs through local.New and through the generated client over the in-process transport (spec 10, Milestone 4 exit)
	AGENTMESH_BUS_TRANSPORT=inproc go test -count=1 -p 1 ./internal/conformance/bus/
check-gates:  ## Prove the negative halves: an unreachable Postgres fails the suites, unit tests exclude the suites, nothing skips, the generator reacts to the schema, the suites fail with no Docker and no variable (needs Docker for the busybox run)
	bash scripts/check-gates.sh
check-gates-selftest:  ## Prove the gate scripts fire: one mutation per check in a throwaway worktree of HEAD (minutes; a dispatch-only ci.yml job, not part of verify)
	bash scripts/check-gates-selftest.sh
docker-image: ## Build the agentmesh:local Docker image (not part of verify)
	docker build -t agentmesh:local .
docker-smoke: ## Build the image and smoke-test it with Docker (not part of verify; a dispatch-only ci.yml job)
	bash scripts/docker-smoke.sh
vet-cross:   ## go vet for linux and windows on amd64 and arm64, and golangci-lint for windows (ported from v1)
	GOOS=linux GOARCH=amd64 go vet ./...
	GOOS=linux GOARCH=arm64 go vet ./...
	GOOS=windows GOARCH=amd64 go vet ./...
	GOOS=windows GOARCH=arm64 go vet ./...
	GOOS=windows golangci-lint run ./...
	$(MAKE) vet-tags
vet-tags:    ## go vet and go build for each external key provider build tag alone and all four together, on linux and windows
	bash scripts/vet-tags.sh
release-check: ## Not part of verify (a dispatch-only ci.yml job). Release tooling: check-pins, the installer, release, render and build-archive harnesses, the local dry run (test-pipeline), vet-cross. Needs bash, git, go, golangci-lint, python3, jq, shasum, OpenSSL 3, ruby, tar, zip, curl; docker on macOS
	bash release/check-pins.sh
	bash release/test-install.sh --self-test
	bash release/test-release.sh
	bash release/test-render.sh
	bash release/build-archive.sh --self-test
	bash release/test-pipeline.sh
	$(MAKE) vet-cross
release-lint: ## actionlint over the workflows and shellcheck over release/, scripts/ and install.sh (not part of verify; a dispatch-only ci.yml job)
	@for t in actionlint shellcheck; do command -v $$t >/dev/null || { echo "release-lint: $$t is not installed"; exit 1; }; done
	actionlint .github/workflows/*.yml
	shellcheck -x release/*.sh scripts/*.sh scripts/testdata/cats-fake/cats .githooks/pre-commit
	shellcheck -s sh install.sh
release-install-check: ## The installer matrix in Docker (RELEASE_INSTALL_ARGS=--quick for one image; not part of verify; a dispatch-only ci.yml job)
	bash release/test-install.sh $(RELEASE_INSTALL_ARGS)
verify:      ## Done gate (CLAUDE.md): build, the m4, m5, m6, m7, m8 and m10 dependency rules, vet, gofmt, lint, spec lint, tidy go.mod, generated-code freshness, unit tests, conformance suites on both engines, gate checks, the enterprise number
	$(MAKE) build
	$(MAKE) build-all
	$(MAKE) build-mcponly
	bash scripts/m10-exit-checks.sh --deps-only
	bash scripts/m5-exit-checks.sh --deps-only
	bash scripts/m6-exit-checks.sh --deps-only
	bash scripts/m4-exit-checks.sh --deps-only
	bash scripts/m7-exit-checks.sh --deps-only
	bash scripts/m8-exit-checks.sh --deps-only
	$(MAKE) vet
	$(MAKE) fmt-check
	$(MAKE) lint
	$(MAKE) spec-lint
	$(MAKE) tidy-check
	$(MAKE) generate-check
	$(MAKE) test
	$(MAKE) test-conformance
	$(MAKE) check-gates
	$(MAKE) pen-check
	@echo "verify: OK"

cats-run:    ## One CATS campaign against a throwaway server (needs cats and Java; not part of verify)
	bash scripts/cats-harness.sh run
cats-selftest: ## The harness selftest with the fake cats (no Java; block 40 of check-gates-selftest runs it once unmutated and under mutation)
	bash scripts/cats-harness-selftest.sh
	bash scripts/cats-precommit-selftest.sh
pen-check:   ## Refuse 0, the documentation number 32473 and a malformed enterprise number in internal/pki (ADR 0019, Decisions 47 and 50; part of verify)
	bash scripts/pen-gate.sh
pen-selftest: ## The pen-check gate against six generated files
	bash scripts/pen-gate-selftest.sh
