# Local OSS substrate for reporium-security.
# $0 / OSS / additive / local-only. Never touches production or live cloud.

COMPOSE ?= docker compose
CF      := -f docker-compose.yml

.PHONY: help up down seed smoke validate logs ps clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'

up: ## Build and start the local substrate (gitserver + pypi stub)
	$(COMPOSE) $(CF) up -d --build gitserver osv-stub

down: ## Stop and remove all substrate containers and volumes
	$(COMPOSE) $(CF) down -v

seed: ## (Re)seed the git server by recreating it (seed is applied at boot)
	$(COMPOSE) $(CF) up -d --build --force-recreate gitserver

smoke: ## Run the smoke test (exercises the real scan path against stubs)
	$(COMPOSE) $(CF) run --build --rm scanner

validate: ## Full cycle: up -> smoke -> down -v (returns smoke exit code)
	@set -e; \
	$(COMPOSE) $(CF) up -d --build --wait gitserver osv-stub; \
	rc=0; $(COMPOSE) $(CF) run --build --rm scanner || rc=$$?; \
	$(COMPOSE) $(CF) down -v; \
	exit $$rc

logs: ## Tail substrate logs
	$(COMPOSE) $(CF) logs -f

ps: ## Show substrate container status
	$(COMPOSE) $(CF) ps

clean: down ## Alias for down (-v)
