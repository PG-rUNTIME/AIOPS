# Everything runs locally with one command: `make up`.
SHELL := /bin/bash
COMPOSE := docker compose --env-file .env -f deploy/compose/docker-compose.yml
SERVICES := ingest-gateway detector-workers correlator agent-gateway router feedback-service control-plane-api chaos-sim mock-servicenow
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo 0.1.0)
REGISTRY ?= ghcr.io/your-org/aiops

.PHONY: help up down logs ps profiles test test-unit test-e2e test-integration evals lint fmt typecheck \
        contracts contracts-check dashboards build token demo-disk-fill demo-memory-leak demo-media sim-stop clean

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-18s %s\n",$$1,$$2}'

.env:
	cp .env.example .env
	@echo "Created .env from .env.example — review it (LLM keys, passwords)."

profiles: .env ## Print the compose profiles `make up` will use
	@./scripts/select-profiles.sh

up: .env ## Start the full stack (profiles auto-selected: GPU→vLLM, hosted key→none, else Ollama)
	COMPOSE_PROFILES=$$(./scripts/select-profiles.sh) $(COMPOSE) up -d --build --wait --wait-timeout 300
	@echo; echo "Grafana http://localhost:3000  vmalert http://localhost:8880  mock ServiceNow http://localhost:8085/mock/state"

down: ## Stop the stack (keeps volumes; `make clean` removes them)
	COMPOSE_PROFILES=core,observability,ai,ai-gpu,chaos,keep,holmes $(COMPOSE) down

clean: ## Stop and delete all volumes
	COMPOSE_PROFILES=core,observability,ai,ai-gpu,chaos,keep,holmes $(COMPOSE) down -v

logs: ## Follow logs (S=service)
	$(COMPOSE) logs -f $(S)

ps:
	$(COMPOSE) ps

test: lint typecheck test-unit evals contracts-check ## Everything CI runs except integration + images

test-unit: ## Unit + e2e tests with coverage gate (≥80%)
	uv run pytest --cov --cov-report=term-missing:skip-covered

test-e2e: ## In-process end-to-end chaos→ticket tests
	uv run pytest tests/e2e -m e2e -v

test-integration: ## Testcontainers tests against real Kafka/Postgres (needs Docker)
	uv run pytest tests/integration -m integration -v -o addopts=""

evals: ## LLM eval suite (replay; AIOPS_EVAL_LIVE=1 for the configured LLM)
	uv run pytest evals -m evals -v

lint:
	uv run ruff check .
	uv run ruff format --check .

fmt:
	uv run ruff format .
	uv run ruff check --fix .

typecheck:
	uv run mypy

contracts: ## Regenerate JSON Schemas, AsyncAPI and OpenAPI
	uv run python scripts/gen_contracts.py

contracts-check:
	uv run python scripts/gen_contracts.py --check

dashboards:
	uv run python scripts/gen_dashboards.py

build: ## Build all images for the local arch
	@for s in $(SERVICES); do \
	  docker buildx build --load -f deploy/docker/Dockerfile --build-arg SERVICE=$$s \
	    --build-arg VERSION=$(VERSION) --build-arg REVISION=$$(git rev-parse HEAD 2>/dev/null) \
	    --build-arg CREATED=$$(date -u +%FT%TZ) -t $(REGISTRY)/$$s:$(VERSION) . || exit 1; done

token: ## Print a dev JWT (ROLES=admin TENANTS='*')
	@uv run python -c "import os;from control_plane.auth import dev_token;print(dev_token(os.environ['AIOPS_AUTH__DEV_SECRET'],'dev-user','$${ROLES:-admin}'.split(','),'$${TENANTS:-*}'.split(',')))"

demo-disk-fill: ## Inject a disk-fill on CI-CORE-DB-01 (fails in 20 min)
	curl -s -X POST 'http://localhost:8090/scenarios/disk_fill?ci_id=CI-CORE-DB-01&fail_in_minutes=20'; echo

demo-memory-leak:
	curl -s -X POST 'http://localhost:8090/scenarios/memory_leak?ci_id=CI-MOBILE-GW-01&fail_in_minutes=20'; echo

demo-media: ## Regenerate docs/media/demo.{gif,mp4} from a real in-process pipeline run
	PYTHONPATH=. uv run python scripts/media/capture_timeline.py
	uv run python scripts/media/render_demo.py

sim-stop:
	curl -s -X DELETE http://localhost:8090/scenarios; echo
