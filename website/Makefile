# The website: Hugo, pinned in go.mod as a tool, with the repository's toolchain.
export GOTOOLCHAIN ?= go1.26.8
HUGO = go tool hugo
OUT ?= ../build/site

.PHONY: site serve chart test check image
site: ## Build the site into ../build/site
	$(HUGO) --gc -d $(OUT)

serve: ## Serve the site with live reload on 127.0.0.1:1313
	$(HUGO) server --bind 127.0.0.1

chart: ## Redraw the home page's chart from data/juist_outline.json
	python3 tools/chart.py

test: ## Test the server
	go test ./server/

check: site test ## Fail if a page holds inline script or style, which the CSP refuses
	@! grep -rlE 'style="|<script>' $(OUT) --include='*.html' || { echo "inline script or style above"; exit 1; }

image: ## Build the image juist-site, with docker or podman, from the repository's root
	cd .. && $$(command -v podman || command -v docker) build -f website/Containerfile -t juist-site .
