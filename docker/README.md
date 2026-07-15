Here's the restructured README with the KVM branch requirement and proper attribution:

---

# malwhere — Docker Environment

## 📋 Table of Contents
1. [Host Requirements](#host-requirements)
2. [Building the CAPE Image (Required First Step)](#building-the-cape-image-required-first-step)
3. [Available Profiles](#available-profiles)
4. [Quickstart](#quickstart)
5. [Service Access](#service-access)
6. [Daily Workflow](#daily-workflow)
7. [Running Static Analysis](#running-static-analysis)
8. [Stopping the Environment](#stopping-the-environment)
9. [Known Issues & Fixes](#known-issues--fixes)

---

## Host Requirements

Before anything else, ensure your system meets these requirements:

- **Ubuntu 24.04.4 LTS** (or compatible Linux distribution)
- **Docker Engine 24.0+** and **Docker Compose v2**
- **KVM enabled**: `egrep -c '(vmx|svm)' /proc/cpuinfo` must return > 0
- **16 GB RAM** minimum (32 GB recommended)
- **`/dev/kvm` accessible**: `ls -la /dev/kvm` should show the device

```bash
# Verify KVM is available
egrep -c '(vmx|svm)' /proc/cpuinfo   # must return > 0
ls -la /dev/kvm                       # must exist

# Install make if not present
sudo apt-get install -y make
```

---

## Building the CAPE Image (Required First Step)

> ⚠️ **IMPORTANT:** The `cape:kvm` image is **not available on Docker Hub** and must be built locally before running the sandbox profile. This is a **one-time step** that takes 15-30 minutes.

### Why KVM?

This project uses **KVM** (Kernel-based Virtual Machine) for hardware-accelerated virtualization instead of VirtualBox. KVM provides:
- **Superior performance** for malware analysis
- **Better stability** with fewer network issues
- **Direct support** in the CAPEv2 community as the recommended approach

### Build Steps

```bash
# 1. Clone the cape-docker build repository (outside the MalWhere project)
cd ~
git clone https://github.com/celyrin/cape-docker.git
cd cape-docker

# 2. Switch to the KVM branch (CRITICAL for our setup!)
git checkout kvm

# 3. Build the image (takes 15-30 minutes on first run)
make all

# 4. Verify the image was created
docker images | grep cape
# Expected: cape    kvm    <id>    <size ~5-6GB>
```

> 📚 **Attribution:** This CAPE Docker setup is based on the excellent work by [celyrin](https://github.com/celyrin) in the [cape-docker](https://github.com/celyrin/cape-docker) repository. We use the `kvm` branch specifically for KVM compatibility with our architecture.

### Troubleshooting the Build

If you encounter build errors:

**Error: "CAPEv2/installer not found"**
```bash
# Clone CAPEv2 source into the directory
cd ~/cape-docker
git clone https://github.com/kevoreilly/CAPEv2.git
make all
```

**Error: "poetry: not found"**
```bash
# Edit the Dockerfile to install poetry before use
cd ~/cape-docker
nano Dockerfile
# Add this line before RUN poetry install:
# RUN pip3 install poetry
# Then rebuild: make all
```

### Post-Build: PostgreSQL Setup

After the image is built and you start the sandbox profile, the `cape-entry` service initializes the database on first boot. If it fails (which can happen if PostgreSQL isn't ready in time), create the role manually:

```bash
# Start the sandbox profile first
docker compose -f docker/docker-compose.yml --profile sandbox up -d cape

# Wait 10 seconds, then create the DB role if needed
docker exec malwhere-cape sudo -u postgres psql -c \
  "CREATE ROLE cape WITH SUPERUSER LOGIN PASSWORD 'SuperPuperSecret';"
docker exec malwhere-cape sudo -u postgres psql -c \
  "CREATE DATABASE cape WITH OWNER cape;"
docker exec malwhere-cape systemctl restart cape-web cape
```

### Verifying CAPE is Running

```bash
# Check all CAPE services
docker exec malwhere-cape systemctl status cape cape-web cape-processor | grep -E "Active|●"

# Test the API
curl -s http://localhost:8000/apiv2/tasks/list/ | python3 -m json.tool
# Expected: {"data": [], "config": "Limit: 10, Offset: None", "buf": 0}
```

> **Note:** CAPE runs in no-auth mode for local development. The web UI is accessible at `http://localhost:8000` without credentials.

---

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
> If CAPE fails after a fresh deploy, run the PostgreSQL setup commands from the Post-Build section above.

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
MISP must run on port 443 directly. The `MISP_BASEURL` env var is ignored if the internal port differs from the external port. Keep the mapping as `443:443`.

### CAPE workers crash on first boot
The `cape-entry` service needs `/work` to exist as a Docker volume. Ensure `cape_work:/work` is defined in both the `volumes:` section and the cape service.

### Static container: `tlsh` module not found
REMnux installs `tlsh` in `/opt/malchive/lib/python3.8/site-packages/`. The Dockerfile copies it to `/usr/local/lib/python3.8/dist-packages/` to make it importable. If this breaks after a REMnux base image update, recheck the path with:
```bash
docker exec malwhere-static find / -name "tlsh*.so" 2>/dev/null
```

### Containers not stopping with `docker compose stop`
Always include the same `--profile` flags used at startup. Without them, Docker Compose cannot resolve which containers belong to the current configuration.

### CAPE build fails with "poetry: not found"
The KVM branch of `celyrin/cape-docker` may have a missing Poetry installation step. Fix it by:
```bash
cd ~/cape-docker
nano Dockerfile
# Add this line before the "RUN poetry install" line:
# RUN pip3 install poetry
# Then rebuild: make all
```

### CAPE build fails with "CAPEv2/installer not found"
The build expects the CAPEv2 source to be present:
```bash
cd ~/cape-docker
git clone https://github.com/kevoreilly/CAPEv2.git
make all
```

---

## Acknowledgements

This project uses the [cape-docker](https://github.com/celyrin/cape-docker) repository by [celyrin](https://github.com/celyrin) for CAPE sandbox containerization, with modifications to use the `kvm` branch for KVM compatibility. We are grateful for their work in making CAPE deployment easier.

---

## License

This project is part of the TFM 2025-2026 at Universidad Complutense de Madrid. All rights reserved.
