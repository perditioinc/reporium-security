# Root passthrough to the local OSS substrate (see local/).
# Additive, local-only, $0. Production and CI are never touched.
#
#   make local-up       start the local substrate
#   make local-smoke    run the smoke test
#   make local-validate up -> smoke -> down -v
#   make local-down     stop and clean up

.PHONY: local-up local-down local-seed local-smoke local-validate local-logs local-ps

local-up:
	$(MAKE) -C local up

local-down:
	$(MAKE) -C local down

local-seed:
	$(MAKE) -C local seed

local-smoke:
	$(MAKE) -C local smoke

local-validate:
	$(MAKE) -C local validate

local-logs:
	$(MAKE) -C local logs

local-ps:
	$(MAKE) -C local ps
