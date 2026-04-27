# Threat Defense System

3rd year cybersecurity multi-agent platform project for ingesting logs, classifying threats, detecting patterns/anomalies, generating attack paths, and coordinating response actions through a live analyst dashboard.

## Features

- Agent 1 (Threat Modeling): attack graph generation with Neo4j and MITRE ATT&CK mapping
- Agent 2 (Classification): ML-based threat classification and confidence scoring
- Agent 3 (Threat Hunting): IOC correlation, anomaly/pattern detection
- Agent 4 (Response Coordinator): automated response flow and analyst support actions
- Analyst Dashboard: Flask + SocketIO UI for monitoring, reviewing threats, and operating agents
- PostgreSQL persistence via SQLAlchemy models in [data/models/models.py](data/models/models.py)
- Redis message bus for inter-agent communication and heartbeat tracking

## Tech Stack

- Python, Flask, Flask-SocketIO
- SQLAlchemy + PostgreSQL
- Redis (pub/sub + heartbeat/status)
- Neo4j (attack graph storage and traversal)
- scikit-learn / NumPy / Pandas (ML)

## Quick Start (Docker, Recommended)

Prerequisites:

- Docker
- Docker Compose
- Git LFS (required if committing model artifacts in data/models)

Compose command compatibility:

- Use docker compose if your system has the Compose plugin.
- Use docker-compose if docker compose is not available.

From the project root:

```bash
docker compose up --build
```

If your environment uses docker-compose:

```bash
docker-compose up --build
```

What this starts:

- Dashboard/API: http://localhost:5000
- PostgreSQL: localhost:5432
- Redis: localhost:6379
- Neo4j Browser: http://localhost:7474
- Neo4j Bolt: localhost:7687

On startup, the app container automatically:

- waits for PostgreSQL
- creates all SQLAlchemy tables from [data/models/models.py](data/models/models.py)
- seeds only [analysts](data/models/models.py) and [external_iocs](data/models/models.py) with the fixed review dataset

Seeded analysts and IOC records are defined in [scripts/init_database.py](scripts/init_database.py).

## Local Development (Without Docker)

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Copy environment template and edit values:

```bash
cp .env.example .env
```

4. Provide environment variables (example below).
5. Run the dashboard:

```bash
python -m dashboard.app
```

## Environment Variables

Core:

- DATABASE_URL (required)
- JWT_SECRET_KEY (required)

Service connectivity:

- REDIS_HOST (default: localhost)
- REDIS_PORT (default: 6379)
- REDIS_DB (default: 0)
- NEO4J_URI (default: bolt://localhost:7687)
- NEO4J_USERNAME (default: neo4j)
- NEO4J_PASSWORD (default: neo4j)

Optional integrations:

- VULNERS_API_KEY (optional, CVE enrichment is disabled if unset)
- SLACK_WEBHOOK_URL
- TEAMS_WEBHOOK_URL
- SLACK_ENABLED (true/false)
- TEAMS_ENABLED (true/false)

Mail:

- MAIL_SERVER
- MAIL_PORT
- MAIL_USE_TLS
- MAIL_USE_SSL
- MAIL_USERNAME
- MAIL_PASSWORD
- MAIL_DEFAULT_SENDER

## Project Structure

- [agents](agents): all 4 core agents
- [dashboard](dashboard): web dashboard + API routes
- [data](data): training data, MITRE dataset, SQLAlchemy models
- [shared](shared): message bus and logging utilities
- [vulnerability_enrichment](vulnerability_enrichment): CVE fetch and scheduler logic
- [scripts](scripts): ML training/retraining scripts

## Notes for Lecturers and Reviewers

- The easiest reproducible setup is Docker Compose.
- The database schema is generated from code-first SQLAlchemy models.
- Neo4j and Redis are included in the compose stack for full agent functionality.

## License

Academic project submission.
