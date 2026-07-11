# malwhere — Docker Environment

## Available Profiles

| Profile | Services | Estimated RAM | When to use |
|---|---|---|---|
| `core` | static, pipeline, navigator | ~4.5 GB | Daily development, static analysis |
| `sandbox` | cape, redis, misp, mysql | ~9.5 GB | Sample execution, dynamic analysis |
| `core` + `sandbox` | All | ~14 GB | Full end-to-end analysis |

> ⚠️ Always include the same `--profile` flags when starting and stopping. Omitting them will leave containers running.

---

## Quickstart

```bash
# 1. Copy environment variables
cp .env.example .env
# Edit .env with your values (MISP API key, passwords)

# 2. Start core services (daily development)
docker compose -f docker/docker-compose.yml --profile core up -d

# 3. Start full environment (when dynamic analysis is needed)
docker compose -f docker/docker-compose.yml --profile core --profile sandbox up -d

# 4. Verify everything is running
docker compose -f docker/docker-compose.yml --profile core --profile sandbox ps
```

---

## Service Access

| Service | URL | Credentials |
|---|---|---|
| CAPE Web UI | http://localhost:8000 | No auth (local dev mode) |
| MISP | https://localhost | admin@admin.test / see `.env` |
| ATT&CK Navigator | http://localhost:4200 | — |
| Pipeline | internal only | — |
| Static analysis | internal only | — |

> **MISP note:** MISP must be accessed at `https://localhost` (port 443 mapped directly).
> Accessing via `https://localhost:8443` will fail due to internal redirect behaviour.
> Accept the self-signed certificate warning in your browser on first access.

> **CAPE note:** PostgreSQL `cape` role must exist before cape-web starts.
> If CAPE fails after a fresh deploy, run:
> ```bash
> docker exec malwhere-cape sudo -u postgres psql -c "CREATE ROLE cape WITH SUPERUSER LOGIN PASSWORD 'SuperPuperSecret';"
> docker exec malwhere-cape sudo -u postgres psql -c "CREATE DATABASE cape WITH OWNER cape;"
> docker exec malwhere-cape systemctl restart cape-web
> ```

---

## Daily Workflow

```bash
# Start everything
docker compose -f docker/docker-compose.yml --profile core --profile sandbox up -d

# Stop safely (preserves all data and volumes)
docker compose -f docker/docker-compose.yml --profile core --profile sandbox stop

# Verify status
docker compose -f docker/docker-compose.yml --profile core --profile sandbox ps
```

---

## Running Static Analysis

```bash
# Enter the static container
docker exec -it malwhere-static bash

# Run the full analyzer against a sample
python3 /scripts/analyze.py --sample /samples/akira.exe --output /reports/akira/ --verbose

# Skip FLOSS for faster run (static strings only)
python3 /scripts/analyze.py --sample /samples/akira.exe --output /reports/akira/ --no-floss

# Or run directly from host
docker exec malwhere-static python3 /scripts/analyze.py \
  --sample /samples/akira.exe \
  --output /reports/akira/ \
  --verbose
```

---

## Verifying the Static Container

```bash
# Check all tools are available
docker exec malwhere-static python3 -c "import pefile, ssdeep, tlsh, rich; print('all imports OK')"
docker exec malwhere-static floss --version
docker exec malwhere-static java -version 2>&1 | head -1
docker exec malwhere-static ghidra-headless 2>&1 | head -2
```

Expected output:
```
all imports OK
floss v3.1.1-0-g3cd3ee6
openjdk version "17.x.x" ...
Java runtime not found (TTY required — normal in headless mode)
```

---

## Stopping the Environment

```bash
# Stop everything safely (data preserved)
docker compose -f docker/docker-compose.yml --profile core --profile sandbox stop

# Stop core only
docker compose -f docker/docker-compose.yml --profile core stop

# ⚠️ DANGER — deletes all volumes and data
docker compose -f docker/docker-compose.yml --profile core --profile sandbox down -v
```

---

## Rebuilding Images

```bash
# Rebuild static image after Dockerfile changes
docker compose -f docker/docker-compose.yml --profile core stop static
docker compose -f docker/docker-compose.yml --profile core rm -f static
docker rmi malwhere-static --force
docker compose -f docker/docker-compose.yml --profile core build --no-cache static
docker compose -f docker/docker-compose.yml --profile core up -d static

# Rebuild pipeline image
docker compose -f docker/docker-compose.yml --profile core stop pipeline
docker compose -f docker/docker-compose.yml --profile core rm -f pipeline
docker rmi malwhere-pipeline --force
docker compose -f docker/docker-compose.yml --profile core build --no-cache pipeline
docker compose -f docker/docker-compose.yml --profile core up -d pipeline
```

---

## Known Issues & Fixes

### MISP redirects to wrong port
MISP must run on port 443 directly. The `MISP_BASEURL` env var is ignored if the
internal port differs from the external port. Keep the mapping as `443:443`.

### CAPE workers crash on first boot
The `cape-entry` service needs `/work` to exist as a Docker volume. Ensure
`cape_work:/work` is defined in both the `volumes:` section and the cape service.

### Static container: `tlsh` module not found
REMnux installs `tlsh` in `/opt/malchive/lib/python3.8/site-packages/`.
The Dockerfile copies it to `/usr/local/lib/python3.8/dist-packages/` to make it
importable. If this breaks after a REMnux base image update, recheck the path with:
```bash
docker exec malwhere-static find / -name "tlsh*.so" 2>/dev/null
```

### Containers not stopping with `docker compose stop`
Always include the same `--profile` flags used at startup. Without them, Docker
Compose cannot resolve which containers belong to the current configuration.

---

## Host Requirements

- Ubuntu 24.04.4 LTS
- Docker Engine 24.0+
- Docker Compose v2
- KVM enabled: `egrep -c '(vmx|svm)' /proc/cpuinfo` must return > 0
- 16 GB RAM minimum
- `/dev/kvm` accessible: `ls -la /dev/kvm`
