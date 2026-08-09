# Network Intrusion Detection System (IDS)

> B.Tech Major Project — Real-time, ML-driven hybrid Intrusion Detection System

A production-grade, real-time Network IDS that ingests live or replayed network traffic, extracts flow-level features, runs a two-stage hybrid ML detection engine, explains every alert with SHAP, persists data in PostgreSQL, and streams live events to a React/TypeScript SOC dashboard.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Native Local Development Stack                        │
│                                                                             │
│  ┌──────────────────┐                                                       │
│  │   Ingestion      │  CAPTURE_MODE=replay  →  ingestion/replay.py         │
│  │   (capture /     │  CAPTURE_MODE=live    →  ingestion/capture.py        │
│  │    replay)       │                                                       │
│  └────────┬─────────┘                                                       │
│           │  push_flow_to_stream()                                          │
│           ▼                                                                 │
│  ┌──────────────────┐                                                       │
│  │  Redis Stream    │  ids:flows   (localhost:6379)                         │
│  │  (local service) │  ids:pcap_jobs (pcap replay jobs)                     │
│  └────────┬─────────┘                                                       │
│           │  XREADGROUP (consumer group)                                    │
│           ▼                                                                 │
│  ┌──────────────────────────────────────┐                                   │
│  │  Worker  (workers/flow_consumer.py)  │                                   │
│  │  ┌────────────────────────────────┐  │                                   │
│  │  │  Feature Extractor             │  │ extract_features() → ndarray      │
│  │  └───────────────┬────────────────┘  │                                   │
│  │                  ▼                   │                                   │
│  │  ┌────────────────────────────────┐  │                                   │
│  │  │  ML Pipeline (pipeline.py)     │  │                                   │
│  │  │  Stage 1: RandomForest         │  │ → (attack_type, confidence)       │
│  │  │  Stage 2: Autoencoder Detector │  │ → (is_anomaly, recon_error)        │
│  │  │  SHAP Explainer                │  │ → shap_values dict                │
│  │  └───────────────┬────────────────┘  │                                   │
│  └──────────────────┼───────────────────┘                                   │
│                     │  write Alert + FlowRecord                             │
│                     ▼                                                       │
│  ┌──────────────────────────────────────┐                                   │
│  │  PostgreSQL                         │  localhost:5433 / 5432             │
│  │  flow_records                        │  date_trunc() aggregations        │
│  │  alerts                              │  JSONB: shap_values, raw_features  │
│  │  threat_intel_cache, reports         │                                   │
│  └──────────────────────────────────────┘                                   │
│                     │  WebSocket broadcast                                  │
│                     ▼                                                       │
│  ┌──────────────────────────────────────┐                                   │
│  │  FastAPI API  (port 8000)            │                                   │
│  │  REST:  /ingest /predict /alerts     │                                   │
│  │  WS:    /ws/alerts  /ws/traffic      │                                   │
│  │  Docs:  /docs                        │                                   │
│  └──────────────────┬───────────────────┘                                   │
│                     │  HTTP + WebSocket                                     │
│                     ▼                                                       │
│  ┌──────────────────────────────────────┐                                   │
│  │  React Dashboard  (port 5173)        │                                   │
│  │  TrafficFeed  AlertPanel  SeverityGauge │                                │
│  └──────────────────────────────────────┘                                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Native Local Setup Guide (Windows / Linux / macOS)

### Prerequisites
1. **Python 3.11+**
2. **Node.js 18+ / npm**
3. **PostgreSQL 16/18** (running on port 5433 or 5432)
4. **Redis 7** (running on port 6379)
5. **Npcap** (for Windows Live Packet Capture)

---

### Step 1: Environment Setup

```powershell
# Copy environment configuration
cp .env.example .env
```

Ensure `.env` matches your local database and Redis credentials:
```ini
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_password_here
POSTGRES_DB=NIDS
DATABASE_URL=postgresql+asyncpg://postgres:your_password_here@localhost:5432/NIDS
REDIS_URL=redis://localhost:6379/0
```

---

### Step 2: Python Backend & Database Migration

```powershell
# Create & activate virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run Database Migrations
alembic upgrade head

# Start FastAPI Backend Server
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

- **API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

---

### Step 3: Background Flow Consumer Worker

Open a second terminal window:

```powershell
# Activate virtual environment
.\venv\Scripts\activate

# Start Flow Consumer Worker
python -m workers.flow_consumer
```

---

### Step 4: React SOC Dashboard

Open a third terminal window:

```powershell
cd frontend
npm install
npm run dev
```

- **Dashboard UI**: [http://localhost:5173](http://localhost:5173)

---

## Environment Variables Configuration

| Variable | Default Value | Description |
|---|---|---|
| `POSTGRES_USER` | `postgres` | Local PostgreSQL username |
| `POSTGRES_PASSWORD` | `your_password_here` | Local PostgreSQL password |
| `POSTGRES_DB` | `NIDS` | PostgreSQL database name |
| `DATABASE_URL` | `postgresql+asyncpg://postgres:your_password_here@localhost:5432/NIDS` | Async SQLAlchemy URL |
| `REDIS_URL` | `redis://localhost:6379/0` | Local Redis connection URL |
| `CAPTURE_MODE` | `replay` | Traffic ingestion mode (`replay` or `live`) |
| `PCAP_PATH` | `data/sample.pcap` | PCAP file path for replay mode |
| `CLASSIFIER_MODEL_PATH` | `ml/artifacts/classifier.joblib` | Stage 1 RandomForest model artifact |
| `AUTOENCODER_MODEL_PATH` | `ml/artifacts/autoencoder.pt` | Stage 2 PyTorch Autoencoder artifact |
| `STAGE1_CONFIDENCE_THRESHOLD` | `0.70` | Confidence threshold for Stage 1 |
| `JWT_SECRET_KEY` | `change_this_to_a_secure_secret_key` | JWT signature secret |
| `LOG_LEVEL` | `info` | Logger verbosity |


---

## Database Management & Alembic Commands

```powershell
# Apply all pending migrations
alembic upgrade head

# Generate a new migration after schema changes
alembic revision --autogenerate -m "describe_change"

# Rollback one migration step
alembic downgrade -1
```

---

## Verification & Testing

Verify that all components are connected and operational:

```powershell
# Health check endpoint
curl http://localhost:8000/health

# Historical alerts query
curl http://localhost:8000/alerts

# Threat Intelligence lookup
curl http://localhost:8000/threat-intel
```
