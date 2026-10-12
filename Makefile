.PHONY: help up down build logs test test-backend test-frontend migrate clean

help:
	@echo "AegisVault Self-Hosted Password Manager Commands:"
	@echo "  make up             Start full stack via Docker Compose"
	@echo "  make down           Stop and remove containers"
	@echo "  make logs           Follow Docker Compose logs"
	@echo "  make test           Run both backend (pytest) and frontend (vitest) tests"
	@echo "  make test-backend   Run backend pytest suite"
	@echo "  make test-frontend  Run frontend Vitest suite"
	@echo "  make migrate        Run database migrations"
	@echo "  make clean          Clean build artifacts and caches"

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f

test: test-backend test-frontend

test-backend:
	python3 -m pytest tests/ -v

test-frontend:
	npx vitest run

migrate:
	python3 -m flask --app wsgi:app db upgrade --directory app/migrations

clean:
	rm -rf dist frontend/dist .pytest_cache __pycache__
