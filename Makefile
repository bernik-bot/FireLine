SVC=services/core-api

.PHONY: install test run signing-key up down logs

install:        ## install dev deps
	cd $(SVC) && pip install -e ".[dev]"

test:           ## run the suite
	cd $(SVC) && pytest -q

run:            ## run the API locally on SQLite
	cd $(SVC) && uvicorn app.main:app --reload

signing-key:    ## print a fresh base64 Ed25519 private key for BLACKBIRCH_SIGNING_KEY
	@python -c "import base64; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; from cryptography.hazmat.primitives import serialization as s; k=Ed25519PrivateKey.generate(); print(base64.b64encode(k.private_bytes(encoding=s.Encoding.Raw,format=s.PrivateFormat.Raw,encryption_algorithm=s.NoEncryption())).decode())"

up:             ## build + start the prod stack (needs .env)
	docker compose -f docker-compose.prod.yml up -d --build

down:           ## stop the prod stack
	docker compose -f docker-compose.prod.yml down

logs:           ## tail api logs
	docker compose -f docker-compose.prod.yml logs -f api
