# Makefile for wg-slim project maintenance tasks

.PHONY: update-bootstrap update-bootstrap-icons update-all clean-pycache test-ci test openapi-client openapi-python-client


# Directories
STATIC_CSS := static/css
STATIC_JS := static/js
STATIC_FONTS := static/css/fonts

# Bootstrap CDN base URLs
BOOTSTRAP_CDN := https://cdn.jsdelivr.net/npm/bootstrap@latest/dist
BOOTSTRAP_ICONS_CDN := https://cdn.jsdelivr.net/npm/bootstrap-icons@latest/font

openapi-server:
	@echo "Generating python-fastapi server into openapi_generated/python-fastapi"
	@mkdir -p openapi_generated
	openapi-generator-cli generate -i openapi.yaml -g python-fastapi -o openapi_generated/python-fastapi; \
	echo "Generated python-fastapi server at openapi_generated/python-fastapi"; \
	

# Paths for OpenAPI client generation and bundling
OPENAPI_FETCH_DIR := openapi_generated/typescript-fetch
OPENAPI_DIST := openapi_generated/dist/openapi-client.js

# Generate + build + bundle the TypeScript `typescript-fetch` client and copy to static
openapi-client:
	@echo "Generating typescript-fetch client into $(OPENAPI_FETCH_DIR)"
	@mkdir -p openapi_generated
	openapi-generator-cli generate -i openapi.yaml -g typescript-fetch -o $(OPENAPI_FETCH_DIR) \
		--additional-properties=supportsES6=true,npmName=@wg-slim/openapi-client,modelPropertyNaming=original; 
	echo "Installing generated client dependencies (local install)"; 
	npm --prefix $(OPENAPI_FETCH_DIR) install; 
	echo "Building generated client (tsc)"; 
	npm --prefix $(OPENAPI_FETCH_DIR) run build; 
	echo "Bundling client into single browser JS ($(OPENAPI_DIST))"; 
	mkdir -p $(dir $(OPENAPI_DIST)); 
	npx --yes esbuild $(OPENAPI_FETCH_DIR)/dist/index.js --bundle --format=iife --global-name=OpenApiClient --outfile=$(OPENAPI_DIST) --minify; 
	echo "Copying bundle to static directory ($(STATIC_JS))"; 
	mkdir -p $(STATIC_JS); 
	cp $(OPENAPI_DIST) $(STATIC_JS)/openapi-client.js; 
	echo "openapi-client built and copied to $(STATIC_JS)/openapi-client.js"; 

# Generate Python client for CLI usage
openapi-python-client:
	@echo "Generating python client into openapi_generated/python-client"
	@mkdir -p openapi_generated
	openapi-generator-cli generate -i openapi.yaml -g python -o openapi_generated/python-client \
		--additional-properties=packageName=wgslim_api_client,projectName=wgslim-api-client; \
	echo "Generated python client at openapi_generated/python-client"

# Update Bootstrap CSS and JS to latest version
update-bootstrap:
	@echo "Updating Bootstrap to latest version..."
	@mkdir -p $(STATIC_CSS) $(STATIC_JS)
	curl -sL $(BOOTSTRAP_CDN)/css/bootstrap.min.css -o $(STATIC_CSS)/bootstrap.min.css
	curl -sL $(BOOTSTRAP_CDN)/js/bootstrap.bundle.min.js -o $(STATIC_JS)/bootstrap.bundle.min.js
	@echo "Bootstrap updated successfully"
	@head -3 $(STATIC_JS)/bootstrap.bundle.min.js | grep -oP 'Bootstrap v[\d.]+' || true

	@echo "Updating Bootstrap Icons to latest version..."
	@mkdir -p $(STATIC_CSS) $(STATIC_FONTS)
	curl -sL $(BOOTSTRAP_ICONS_CDN)/bootstrap-icons.min.css -o $(STATIC_CSS)/bootstrap-icons.min.css
	curl -sL $(BOOTSTRAP_ICONS_CDN)/fonts/bootstrap-icons.woff -o $(STATIC_FONTS)/bootstrap-icons.woff
	curl -sL $(BOOTSTRAP_ICONS_CDN)/fonts/bootstrap-icons.woff2 -o $(STATIC_FONTS)/bootstrap-icons.woff2
	@echo "Bootstrap Icons updated successfully"
	@# Fix font paths in CSS (CDN uses ../fonts/, we use fonts/)
	sed -i 's|url("../fonts/|url("fonts/|g' $(STATIC_CSS)/bootstrap-icons.min.css
	@echo "Fixed font paths in bootstrap-icons.min.css"


test:  
	rm -rf openapi_generated /tmp/wg-slim-build.lock /tmp/wg-slim-rm.lock
	$(MAKE) openapi-client
	$(MAKE) openapi-server
	$(MAKE) openapi-python-client
	ruff check --fix --exclude openapi_generated
	ruff format --exclude openapi_generated
	$(MAKE) test-ci
	$(MAKE) test-integration

test-ci:
	python3 -m pytest tests/ --ignore=tests/integration -ra -n auto

test-integration:
	python3 -m pytest tests/integration -ra -n auto

test-docker:
	# TODO: Nest
	docker build --no-cache -f Dockerfile.test -t wg-slim-tester .
	docker run --rm --network host --privileged -v /var/run/docker.sock:/var/run/docker.sock wg-slim-tester
