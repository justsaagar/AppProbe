PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
export PYTHONPATH := backend

.PHONY: setup test lint run scan

setup:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r backend/requirements.txt
	mkdir -p workspace/uploads workspace/scans workspace/artifacts workspace/screenshots workspace/logs workspace/reports

test:
	cd backend && PYTHONPATH=. $(CURDIR)/$(BIN)/pytest tests -q

lint:
	$(BIN)/ruff check backend/app backend/tests

run:
	$(BIN)/uvicorn app.main:app --app-dir backend --reload --host 0.0.0.0 --port 8000

scan:
	@if [ -z "$(FILE)" ]; then echo "Usage: make scan FILE=path/to/app.apk"; exit 1; fi
	$(BIN)/python -m app.cli scan "$(FILE)"
