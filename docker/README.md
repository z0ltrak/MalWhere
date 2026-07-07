# malwhere — Docker Environment

## Available Profiles

| Profile | Services | Estimated RAM | When to use |
|---|---|---|---|
| `core` | static, pipeline, navigator | ~4.5 GB | Daily development, static analysis |
| `sandbox` | cape, redis, misp, mysql | ~9.5 GB | Sample execution, dynamic analysis |
| `core` + `sandbox` | All | ~14 GB | Full end-to-end analysis |

## Quickstart

```bash
# 1. Copy environment variables
cp .env.example .env
# Edit .env with your values

# 2. Start core services (daily development)
docker compose --profile core up -d

# 3. Verify everything is running
docker compose ps

# 4. Start sandbox when dynamic analysis is needed
docker compose --profile sandbox up -d
```

## Service Access

| Service | URL | Credentials |
|---|---|---|
| CAPE Web UI | http://localhost:8000 | admin / admin (change on first login) |
| MISP | https://localhost:8443 | admin@admin.test / see .env |
| ATT&CK Navigator | http://localhost:4200 | — |

## Running Static Analysis Manually

```bash
# Enter the static container
docker exec -it malwhere-static bash

# Inside the container
python3 /scripts/analyze.py --sample /samples/akira.exe --output /reports/akira/
```

## Stopping the Environment

```bash
# Core only
docker compose --profile core down

# Everything
docker compose --profile core --profile sandbox down

# Everything + delete volumes (WARNING: deletes all results)
docker compose --profile core --profile sandbox down -v
```

## Host Requirements

- Ubuntu 24.04.4 LTS
- Docker Engine 24.0+
- Docker Compose v2
- KVM enabled (`egrep -c '(vmx|svm)' /proc/cpuinfo` > 0)
- 16 GB RAM minimum
- `/dev/kvm` accessible (`ls -la /dev/kvm`)
