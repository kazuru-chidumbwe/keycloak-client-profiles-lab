PY ?= ./venv/bin/python

.PHONY: venv setup run-default run-guidance run-all trap test lint clean

venv:
	python3 -m venv venv && ./venv/bin/pip install -q -e '.[dev]'

setup:
	bash setup-keycloak.sh

run-default:
	$(PY) probes.py S0

run-guidance:
	$(PY) probes.py S1

run-all:
	$(PY) probes.py S2L

trap:
	$(PY) trap_anyclient.py

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check kclab probes.py trap_anyclient.py tests

clean:
	-docker rm -f kclab-kc
	-docker volume rm kclab-tls
	@echo "lab runs and the lab CA stay in $${KCLAB_HOME:-$$HOME/oauthc}; remove that folder yourself when done"
