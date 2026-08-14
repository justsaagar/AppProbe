PYTHON ?= python3
BACKEND_DIR := backend
export PYTHONPATH := $(BACKEND_DIR)

.PHONY: setup test lint run scan help

help:
	@echo "AppProbe Milestone 1 targets:"
	@echo "  make setup          Install backend dependencies"
	@echo "  make test           Run unit and integration tests"
	@echo "  make lint           Run ruff"
	@echo "  make run            Start the FastAPI server"
	@echo "  make scan FILE=...  Scan a local APK/AAB/IPA via CLI"

setup:
	$(PYTHON) -m pip install -r $(BACKEND_DIR)/requirements.txt

test:
	cd $(BACKEND_DIR) && $(PYTHON) -m pytest -q

lint:
	cd $(BACKEND_DIR) && $(PYTHON) -m ruff check app tests

run:
	cd $(BACKEND_DIR) && $(PYTHON) -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

scan:
	@if [ -z "$(FILE)" ]; then echo "Usage: make scan FILE=./example.apk"; exit 1; fi
	$(PYTHON) -m app.cli scan "$(FILE)"
