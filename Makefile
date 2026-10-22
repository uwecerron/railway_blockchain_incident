PY ?= python3
ARGS ?=

.PHONY: install dev test lint scan trace report docker-build docker-trace clean-cache

install:            ## install the CLI (railway-trace) into the current environment
	$(PY) -m pip install .

dev:                ## editable install + lint tools
	$(PY) -m pip install -e ".[dev]"

test:               ## offline unit tests (no API key needed)
	$(PY) -m unittest discover -s tests -t . -v

lint:
	$(PY) -m pyflakes railway_trace tests

scan:               ## fail if an API key is present anywhere outside .env
	$(PY) -m railway_trace scan-secrets

trace:              ## full pipeline: fetch -> price -> hops -> report  (pass ARGS="--address 0x... --since ...")
	$(PY) -m railway_trace all $(ARGS)

report:
	$(PY) -m railway_trace report $(ARGS)

docker-build:
	docker build -t railway-trace .

docker-trace:       ## run in Docker with your .env, results in ./out
	docker run --rm --env-file .env -v "$(PWD)/out:/app/out" railway-trace all $(ARGS)

clean-cache:        ## drop cached API responses (raw/ and reports are kept)
	$(PY) -c "import shutil; shutil.rmtree('out/cache', ignore_errors=True)"
