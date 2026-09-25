# Makefile for wg-slim project maintenance tasks

.PHONY: update-bootstrap update-bootstrap-icons update-all clean-pycache test-ci test \
        openapi openapi-server openapi-client openapi-python-client openapi-clean \
        install-generated test-integration test-docker lint

# Everything generated from openapi.yaml. The stamp files let make skip codegen
# when openapi.yaml has not changed since the last run - a full regeneration is
# three Java/npm passes and used to run on every `make test`.
# Use `make openapi-clean openapi` to force a rebuild from scratch.
STAMP_DIR := openapi_generated/.stamps

# Overridable so callers can point at a specific interpreter's pip. Debian
# images need PIP_BREAK_SYSTEM_PACKAGES=1 in the environment (see Dockerfile.test).
PIP ?= pip

# Directories
STATIC_CSS := static/css
STATIC_JS := static/js
STATIC_FONTS := static/css/fonts

# Bootstrap versions vendored in static/. Pinned so `make update-bootstrap`
# is reproducible; bump them deliberately to upgrade.
BOOTSTRAP_VERSION := 5.3.8
BOOTSTRAP_ICONS_VERSION := 1.13.1

# Bootstrap CDN base URLs
BOOTSTRAP_CDN := https://cdn.jsdelivr.net/npm/bootstrap@$(BOOTSTRAP_VERSION)/dist
BOOTSTRAP_ICONS_CDN := https://cdn.jsdelivr.net/npm/bootstrap-icons@$(BOOTSTRAP_ICONS_VERSION)/font

# Paths for OpenAPI client generation and bundling
OPENAPI_FETCH_DIR := openapi_generated/typescript-fetch
OPENAPI_DIST := openapi_generated/dist/openapi-client.js

# Regenerate everything openapi.yaml feeds, then (re)install the Python packages.
openapi: openapi-server openapi-client openapi-python-client

openapi-server: $(STAMP_DIR)/server
$(STAMP_DIR)/server: openapi.yaml
	mkdir -p $(STAMP_DIR)
	JAVA_OPTS="-Dlog.level=ERROR" openapi-generator-cli generate -i openapi.yaml -g python-fastapi -o openapi_generated/python-fastapi
	touch $@

# Generate + build + bundle the TypeScript `typescript-fetch` client and copy to static
openapi-client: $(STAMP_DIR)/client
$(STAMP_DIR)/client: openapi.yaml
	mkdir -p $(STAMP_DIR)
	JAVA_OPTS="-Dlog.level=ERROR" openapi-generator-cli generate -i openapi.yaml -g typescript-fetch -o $(OPENAPI_FETCH_DIR) \
		--additional-properties=supportsES6=true,npmName=@wg-slim/openapi-client,modelPropertyNaming=original
	npm --prefix $(OPENAPI_FETCH_DIR) install
	npm --prefix $(OPENAPI_FETCH_DIR) run build
	mkdir -p $(dir $(OPENAPI_DIST))
	npx --yes esbuild $(OPENAPI_FETCH_DIR)/dist/index.js --bundle --format=iife --global-name=OpenApiClient --outfile=$(OPENAPI_DIST) --minify
	mkdir -p $(STATIC_JS)
	cp $(OPENAPI_DIST) $(STATIC_JS)/openapi-client.js
	touch $@

# Generate Python client for CLI usage
openapi-python-client: $(STAMP_DIR)/python-client
$(STAMP_DIR)/python-client: openapi.yaml
	mkdir -p $(STAMP_DIR)
	JAVA_OPTS="-Dlog.level=ERROR" openapi-generator-cli generate -i openapi.yaml -g python -o openapi_generated/python-client \
		--additional-properties=packageName=wgslim_api_client,projectName=wgslim-api-client
	touch $@

openapi-clean:
	rm -rf openapi_generated static/js/openapi-client.js

# Install the generated packages so `openapi_server` and `wgslim_api_client`
# import normally, for both python and pyright, instead of being reached via a
# sys.path hack. Deliberately NOT editable: setuptools installs an editable
# python-client behind a PEP 660 import hook that pyright cannot follow, which
# is what `--config-settings editable_mode=compat` used to work around. A plain
# install is what CI and the container use, so dev matches them. Rerun this
# after regenerating; `make test` does it for you.
install-generated: $(STAMP_DIR)/server $(STAMP_DIR)/python-client
	$(PIP) install --force-reinstall --no-deps openapi_generated/python-fastapi
	$(PIP) install --force-reinstall --no-deps openapi_generated/python-client

# Update Bootstrap CSS and JS to latest version
update-bootstrap:
	@echo "Updating Bootstrap to $(BOOTSTRAP_VERSION)..."
	mkdir -p $(STATIC_CSS) $(STATIC_JS)
	curl -sL $(BOOTSTRAP_CDN)/css/bootstrap.min.css -o $(STATIC_CSS)/bootstrap.min.css
	curl -sL $(BOOTSTRAP_CDN)/js/bootstrap.bundle.min.js -o $(STATIC_JS)/bootstrap.bundle.min.js

	@echo "Updating Bootstrap Icons to $(BOOTSTRAP_ICONS_VERSION)..."
	mkdir -p $(STATIC_CSS) $(STATIC_FONTS)
	curl -sL $(BOOTSTRAP_ICONS_CDN)/bootstrap-icons.min.css -o $(STATIC_CSS)/bootstrap-icons.min.css
	curl -sL $(BOOTSTRAP_ICONS_CDN)/fonts/bootstrap-icons.woff -o $(STATIC_FONTS)/bootstrap-icons.woff
	curl -sL $(BOOTSTRAP_ICONS_CDN)/fonts/bootstrap-icons.woff2 -o $(STATIC_FONTS)/bootstrap-icons.woff2


test:
	rm -f /tmp/wg-slim-build.lock /tmp/wg-slim-rm.lock
	$(MAKE) openapi
	$(MAKE) install-generated
	$(MAKE) lint
	$(MAKE) test-ci
	$(MAKE) test-integration

lint:
	ruff check --fix --exclude openapi_generated
	ruff format --exclude openapi_generated

test-ci:
	python3 -m pytest tests/ --ignore=tests/integration -ra -n auto

test-integration:
	python3 -m pytest tests/integration -ra -n auto

test-docker:
	docker build --no-cache -f Dockerfile.test -t wg-slim-tester .
	docker run --rm --privileged -v /var/run/docker.sock:/var/run/docker.sock wg-slim-tester
