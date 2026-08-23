
---

# malwhere: Docker Environment

## Table of Contents
1. [Host Requirements](#host-requirements)
2. [Host Setup: libvirt/KVM](#host-setup-libvirtkvm)
3. [Building the CAPE Image (Required First Step)](#building-the-cape-image-required-first-step)
4. [Creating the Guest VM](#creating-the-guest-vm)
5. [Available Profiles](#available-profiles)
6. [Quickstart](#quickstart)
7. [Service Access](#service-access)
8. [Daily Workflow](#daily-workflow)
9. [Running Static Analysis](#running-static-analysis)
10. [Resubmission Loop](#resubmission-loop)
11. [Verifying the Static Container](#verifying-the-static-container)
12. [Stopping the Environment](#stopping-the-environment)
13. [Rebuilding Images](#rebuilding-images)
14. [Known Issues & Fixes](#known-issues--fixes)

---

## Host Requirements

Before anything else, ensure your system meets these requirements:

- **Ubuntu 24.04.4 LTS** (or compatible Linux distribution)
- **Docker Engine 24.0+** and **Docker Compose v2** (`docker.io` and
  `docker-compose-plugin` from apt satisfy both)
- **KVM enabled**: `egrep -c '(vmx|svm)' /proc/cpuinfo` must return > 0
- **16 GB RAM** minimum (32 GB recommended)
- **`/dev/kvm` accessible**: `ls -la /dev/kvm` should show the device

```bash
# Install Docker if not present
sudo apt-get install -y docker.io docker-compose-plugin

# Verify KVM is available
egrep -c '(vmx|svm)' /proc/cpuinfo   # must return > 0
ls -la /dev/kvm                       # must exist

# Install make if not present
sudo apt-get install -y make
```

Installing `docker.io` does **not** add you to the `docker` group, so every
`docker`/`docker compose` command needs `sudo` until you do this yourself:

```bash
sudo usermod -aG docker $USER
```

Then **log out and back in** (or `newgrp docker`) for it to take effect —
same as the `libvirt`/`kvm` group note below.

---

## Host Setup: libvirt/KVM

`cape` and `inetsim` run with `network_mode: host` and talk directly to the
HOST's libvirt/KVM: docker-compose cannot set this part up, because it's
outside any container. Run this once, before building or starting anything:

```bash
sudo ./docker/scripts/host-prereqs.sh
```

It installs qemu-kvm/libvirt if missing, verifies `/dev/kvm` actually works
(not just exists), makes sure libvirt's default network is up, and, the
part that matters for reproducibility: **discovers your machine's actual
bridge interface and gateway IP** (this varies per machine, it's not
guessable in advance) and writes `LIBVIRT_GATEWAY`/`LIBVIRT_BRIDGE` into
`docker/.env`. CAPE's own conf files and inetsim's entrypoint both read
these via `%(ENV:LIBVIRT_GATEWAY)s`-style interpolation, so nothing needs
hand-editing afterwards. Safe to re-run any time.

If it added you to the `libvirt`/`kvm` groups, **log out and back in**
before continuing: group membership doesn't apply to your current shell
session otherwise (`virsh` will fail with "Permission denied" until you do).

---

## Building the CAPE Image (Required First Step)

> **IMPORTANT:** The `cape:kvm` image is **not available on Docker Hub** and must be built locally before running the sandbox profile. This is a **one-time step** that takes 15-30 minutes.

### Why KVM?

This project uses **KVM** (Kernel-based Virtual Machine) for hardware-accelerated virtualization instead of VirtualBox. KVM provides:
- **Superior performance** for malware analysis
- **Better stability** with fewer network issues
- **Direct support** in the CAPEv2 community as the recommended approach

### Build Steps

```bash
# 1. Clone our fixed fork of the cape-docker build repository (outside the MalWhere project)
cd ~
git clone git@github.com:z0ltrak/kvm-cape-docker.git
cd kvm-cape-docker

# 2. Switch to the KVM branch (CRITICAL for our setup!)
git checkout kvm

# 3. Build the image (takes 15-30 minutes on first run)
# `make all` inits the CAPEv2 submodule for you -- see Troubleshooting below
# if you're on the upstream repo instead and hit "CAPEv2/installer not found".
make all

# 4. Verify the image was created
docker images | grep cape
# Expected: cape    kvm    <id>    <size ~5-6GB>
```

> **Attribution:** This CAPE Docker setup is based on the excellent work by [celyrin](https://github.com/celyrin) in the [cape-docker](https://github.com/celyrin/cape-docker) repository. We use our own fork, [z0ltrak/kvm-cape-docker](https://github.com/z0ltrak/kvm-cape-docker) (`kvm` branch), which bakes in fixes for two build failures hit bringing this up on a second machine -- see Troubleshooting below for what they were, in case you're working from upstream instead.

### Troubleshooting the Build

Our fork above already fixes both of these. They're documented here in case
you're building from upstream `celyrin/cape-docker` instead:

**Error: "CAPEv2/installer not found"**

CAPEv2 is a git submodule; a plain `git clone` leaves it empty. Either clone
with `--recurse-submodules`, or:
```bash
cd ~/cape-docker
git submodule update --init --recursive
make all
```

**Error: "poetry: not found"**
```bash
# Edit the Dockerfile to install poetry before use
cd ~/cape-docker
nano Dockerfile
# Add this line before RUN poetry install:
# RUN sudo pip3 install poetry
# Then rebuild: make all
```

### Post-Build: PostgreSQL Setup

After the image is built and you start the sandbox profile, the `cape` container initializes its PostgreSQL/MongoDB databases (`cape_task_db`, `cape_postgres_data`, `cape_mongo_data`) on first boot. If it fails (which can happen if PostgreSQL isn't ready in time), create the role manually:

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

## Creating the Guest VM

> **This step cannot be automated by docker-compose or any script in this
> repo**: it's an interactive Windows install done once per machine. Skip
> it and CAPE starts up only to crash-loop with `CuckooStartupError: ...
> Domain not found: no domain with matching name 'win10x64'`, `kvm.conf`
> names the machine `win10x64`, but naming it in config doesn't create it.

**Windows ISO**: Microsoft pulled the Windows 10 Enterprise evaluation from its
default Evaluation Center flow (Windows 10 hit end of support Oct 2025), grab
the plain consumer ISO instead, from **microsoft.com/software-download/windows10iso**.
No sign-in, no product key needed; it installs and runs fully functional
unactivated (just a desktop watermark), which is irrelevant for a sandbox VM.
Never vendor the ISO in this repo: same reasoning as `cape:kvm` not being
published to a registry: it's a multi-GB proprietary binary you're not
licensed to redistribute, so each machine fetches its own.

**Step 1 — storage pool.** Skip if `virsh pool-list --all` already shows one.
```bash
virsh pool-define-as default dir --target /var/lib/libvirt/images
virsh pool-build default && virsh pool-start default && virsh pool-autostart default
```

**Step 2 — make the ISO readable.** The `libvirt-qemu` user needs traversal
into wherever you downloaded it, which your home directory normally blocks
(as the file's owner, no sudo needed):
```bash
chmod o+x ~ && chmod o+rx ~/Downloads && chmod o+r ~/Downloads/your-win10.iso
```

**Step 3 — create the VM, with no network attached yet.** On the **host**
(not inside a container), named exactly `win10x64` (matches
`docker/cape/work/conf/kvm.conf`'s `[win10x64]` section: rename both together
if you change it). Pick a disk size that fits your free space (`df -h
/var/lib/libvirt` first), 50GB is comfortable for Windows 10 + agent + tools.
```bash
virt-install --name win10x64 --os-variant win10 --ram 4096 --vcpus 2 \
  --disk pool=default,size=50,format=qcow2 --cdrom ~/Downloads/your-win10.iso \
  --network none --graphics vnc,listen=127.0.0.1 \
  --noautoconsole
```
`--network none` is deliberate, not an oversight, see step 5.

**Step 4 — click through Setup.** Connect with `virt-viewer --connect
qemu:///system win10x64`. It reboots partway through (copies files, then
continues from disk instead of the ISO); the domain may show `shut off`
rather than auto-restarting depending on whether Windows issued a reboot or
a full poweroff — `virsh start win10x64` brings it back either way, boot
order is `hd`-first by default so it resumes instead of re-running Setup.

**Step 5 — offline local account (no Microsoft email).** Because the VM has
no network device yet, Windows Setup can't reach the internet and skips
straight to a **local** account: just a username and password, no
Microsoft email, no online sign-in. This is the easiest reliable way to get
that flow — trying to click past the "connect to a network" screen while a
NIC *is* present is finicky and varies by ISO build. Finish Setup this way,
reach the desktop, then attach the network for real:
```bash
virsh attach-interface win10x64 --type network --source default \
  --model e1000 --config --live
```
`--config --live` attaches it now **and** makes it persist across reboots.
**Use `model=e1000`, not the virtio default** — Windows 10 has no built-in
virtio-net driver, so a virtio NIC shows up unrecognized and "Change adapter
settings" is empty; e1000 has an in-box driver and, as a side benefit,
doesn't announce itself as a VM to samples doing basic anti-analysis checks
the way "Red Hat VirtIO Ethernet Adapter" does.

**Step 6 — static IP, with DNS pointed at the gateway.** Network settings →
your Ethernet adapter → Edit IP settings → Manual → IPv4 on:
| Field | Value |
|---|---|
| IP address | `192.168.122.100` (must match `GUEST_VM_IP` in `docker/.env`) |
| Subnet mask | `255.255.255.0` |
| Gateway | `192.168.122.1` |
| Preferred DNS | `192.168.122.1` — **same as the gateway, not `8.8.8.8` or anything else** |

That IP is `inetsim` (matching `routing.conf`'s `[inetsim] server`), which is
the sandbox's fake internet — it answers *every* DNS query itself. Point DNS
anywhere else and the guest has no route to a real DNS server (this network
is deliberately contained, see `routing.conf`), so nothing resolves and the
detonation looks like the malware silently failed instead of being
sandboxed correctly.

**Step 7 — auto-login.** `netplwiz`'s checkbox doesn't render on some
Windows 10 builds; the reliable fallback is the registry directly (elevated
cmd):
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d "YOUR_USERNAME" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d "YOUR_PASSWORD" /f
```

**Step 8 — disable Windows Update, Defender, and the firewall.** Defender:
real-time protection, cloud-delivered protection, automatic sample
submission, tamper protection — all off, a live Defender will
flag/quarantine samples before CAPE's agent gets a look at them. Firewall:
```cmd
netsh advfirewall set allprofiles state off
```

**Step 9 — fully disable UAC**, not just the "Never notify" slider, that
slider still leaves processes with a filtered (non-admin) token. Confirmed
via the agent's own `is_user_admin` field in its status response:
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
```
Needs a reboot to take effect. This matters concretely for this sample set:
RoningLoader disables Driver Signature Enforcement and installs a kernel
driver, which needs a real admin token, not a filtered one.

**Step 10 — install Python 3 and the CAPE agent.**
1. Download the Python **3.12.x, 64-bit** installer directly from
   [python.org/downloads/windows](https://www.python.org/downloads/windows/)
   — look for `python-3.12.x-amd64.exe`. Don't use the Microsoft Store
   package: it installs under a per-user execution-alias path that's less
   predictable for a background process expected to survive every logon.
   Check **"Add python.exe to PATH"** during install.
2. Save
   [`agent.py`](https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/agent/agent.py)
   as `C:\agent.py`.
3. Press **Win+R**, type `shell:startup`, Enter — this opens the current
   user's Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`).
   Right-click inside it → New → Shortcut.
4. For the target, use the **full path** to `pythonw.exe`, not just
   `pythonw.exe` — Startup-folder shortcuts don't reliably resolve `PATH` at
   logon, even though PATH itself was checked during install. Two likely
   locations depending on how you installed it:
   - Per-user (default): `C:\Users\YOUR_USERNAME\AppData\Local\Programs\Python\Python312\pythonw.exe C:\agent.py`
   - For all users: `C:\Program Files\Python312\pythonw.exe C:\agent.py`

   If unsure which applies, open an elevated cmd and run `where pythonw` to
   get the exact path.
5. Verify from the **host** once it's running:
   ```bash
   curl -s http://192.168.122.100:8000/ | python3 -m json.tool
   # expect: {"message": "CAPE Agent!", ..., "is_user_admin": true}
   ```

**Step 11 — snapshot.** With the VM in exactly this state: logged in, agent
listening, nothing left to configure: take a **live** snapshot (VM running,
not shut down). CAPE reverts straight into this ready state instead of
cold-booting per task:
```bash
virsh snapshot-create-as win10x64 clean_baseline --atomic
```
`docker/cape/work/conf/kvm.conf`'s `[win10x64]` section already ships with
`snapshot = clean_baseline` active by default (not commented out — nothing
to edit there unless you renamed the domain or picked a different snapshot
name, in which case update both to match).

Only after this exists does `docker exec malwhere-cape virsh -c qemu:///system list --all`
show the domain, and only then will `cape.service` get past its startup
snapshot check.

### Automating this / getting a pre-built VM

There's no automated or downloadable-VM shortcut for this today. Two things
worth knowing if that's the goal:

- **Steps 4–10 above (Windows Setup + hardening + agent install) can be
  scripted** with a Windows unattended-setup answer file (`autounattend.xml`,
  fed to `virt-install` as a second virtual CD-ROM) plus a first-logon script
  doing the same `reg add`/`netsh` commands already documented here. That
  would turn most of this page into "boot the VM, wait" instead of manual
  clicking. It hasn't been built for this repo yet — it needs testing
  against an actual Windows install to get right (answer-file schemas are
  picky about the exact ISO build), which isn't something to author blind.
- **Distributing the finished VM disk image itself (e.g. via Google Drive)
  is not a good idea, and not just for file-size reasons**: it would contain
  an actual installed copy of Windows. The free consumer ISO's terms cover
  *you* installing Windows, not you redistributing a customized copy of it
  to other people — the same reasoning that already keeps the ISO itself out
  of this repo applies more strongly to a full installed disk image. If the
  goal is letting a teacher stand this up quickly, the unattended-install
  script above (pure scripts/config, no Microsoft IP in it) is the
  legitimate way to get them a fast, low-effort build of their own.

### A libvirt host quirk worth knowing about

If `virsh`/CAPE intermittently fail with `Permission denied` or `Connection
refused` on `/var/run/libvirt/libvirt-sock`, and the socket's group keeps
flip-flopping between `libvirt` and something unrelated (e.g. `nm-openvpn`)
independent of anything you're doing: that's what happens when something
else on the host recreates `libvirtd.socket` mid-session (its unit uses
`SocketMode=0660`/`SocketGroup=libvirt`, freshly resolved from `/etc/group`
each time it's (re)created). The `cape` image's own fixes (masking its
internal `libvirtd` so it can't compete for the same bind-mounted socket, and
realigning its `libvirt` group GID to match the host's on every service
start: see `docker/cape/Dockerfile`) handle the container side automatically.
If it's still happening, `sudo systemctl restart libvirtd.socket libvirtd.service`
on the host resolves it: a "Job failed" message from restarting both units
together is usually just an ordering race, not a real failure; check
`systemctl is-active libvirtd.socket libvirtd.service` afterward before
assuming it didn't work.

---

## Available Profiles

| Profile | Services | Estimated RAM | When to use |
|---|---|---|---|
| `core` | static, pipeline, navigator | ~4.5 GB | Daily development, static analysis |
| `sandbox` | cape, inetsim, redis, misp, mysql | ~9.5 GB | Sample execution, dynamic analysis |
| `core` + `sandbox` | All | ~14 GB | Full end-to-end analysis |

> Always include the same `--profile` flags when starting and stopping. Omitting them will leave containers running.

---

## Quickstart

```bash
# 1. Copy environment variables, then edit docker/.env with your MISP API
#    key and passwords (leave LIBVIRT_GATEWAY/LIBVIRT_BRIDGE as-is, the
#    next step overwrites just those two lines in place with real values,
#    without touching what you just set here)
cp docker/.env.example docker/.env

# 2. Host libvirt/KVM setup, see "Host Setup: libvirt/KVM" above (one-time,
#    needs sudo; safe to re-run). Writes the real LIBVIRT_GATEWAY/
#    LIBVIRT_BRIDGE into docker/.env, discovered from this machine.
sudo ./docker/scripts/host-prereqs.sh

# 3. Start core services (daily development)
docker compose -f docker/docker-compose.yml --profile core up -d

# 4. Start full environment (when dynamic analysis is needed, requires the
#    cape:kvm image built and the win10x64 guest VM created, see above)
docker compose -f docker/docker-compose.yml --profile core --profile sandbox up -d

# 5. Verify everything is running
docker compose -f docker/docker-compose.yml --profile core --profile sandbox ps
```

---

## Service Access

| Service | URL | Credentials |
|---|---|---|
| CAPE Web UI | http://localhost:8000 | No auth (local dev mode) |
| MISP | https://localhost | admin@admin.test / see `.env` |
| ATT&CK Navigator | http://localhost:4200 | N/A |
| Pipeline | internal only | N/A |
| Static analysis | internal only | N/A |

> **MISP note:** MISP must be accessed at `https://localhost` (port 443 mapped directly).
> Accessing via `https://localhost:8443` will fail due to internal redirect behaviour.
> Accept the self-signed certificate warning in your browser on first access.
> `inetsim` also wants port 443, see Known Issues below, "`inetsim` and `misp` both want port 443", for how the two now coexist.

> **MISP login gotcha:** the real bootstrap admin account is `admin@admin.test`,
> not the `MISP_EMAIL` value set in docker-compose.yml (`admin@malwhere.local`),
> MISP's own image defaults win over that env var on first init. Worse,
> `MISP_PASSWORD`/`MISP_ADMIN_PASSWORD` doesn't reliably apply to that account
> either, so "log in with the password from `.env`" may just fail. If it does,
> reset both credentials directly against the running container, this is a
> live fix against the `mysql_data` volume, not something a `docker-compose.yml`
> change can set once and forget:
> ```bash
> docker exec malwhere-misp /var/www/MISP/app/Console/cake user change_pw admin@admin.test 'YOUR_PASSWORD'
> docker exec malwhere-misp /var/www/MISP/app/Console/cake user change_authkey admin@admin.test 'YOUR_API_KEY'
> ```
> Same category of issue as the MISP MySQL password drift (see Known Issues
> below): if `mysql_data` is ever rebuilt from scratch, both resets need
> to be redone.

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

## Resubmission Loop

`run_pipeline.py` at the repo root runs this whole loop automatically as
part of a normal end-to-end analysis (on by default, `--skip-resubmit`
opts out) -- everything below is the manual, step-by-step version of what
it does, useful for debugging one stage in isolation or resubmitting
against an already-parsed dynamic report without rerunning detonation.

Multi-stage malware drops payloads with real capabilities of their own,
this sample set's own RoningLoader drops a rootkit driver (`vally3dka.sys`),
an AV-killer DLL (`goldendays.dll`), and a Gh0st RAT client. Without this
loop, dropped files only ever show up as hashes in `normalized_iocs.json`;
none of their own imports, strings, or ATT&CK techniques get extracted. The
loop is two independent halves, split across the two `core` containers by
what each one has installed: `static` has pefile/YARA/FLOSS/Ghidra,
`pipeline`'s normalize+map stages are pure-stdlib:

```
dynamic/scripts/parse_cape.py --resubmit-dir
        │  (runs on the host: pure stdlib, and CAPE storage +
        │   docker/resubmit_queue are both host-accessible bind mounts)
        ▼
docker/resubmit_queue/{manifest,artifacts}/
        │
        ▼
static/scripts/process_resubmissions.py           (inside `static`, needs pefile etc.)
        │  reads /resubmit (ro), writes static/reports/{family}/{sha256}_static.json
        │  tagged with a resubmission_lineage block (parent_hash, discovery_mechanism, ...)
        ▼
pipeline/process_resubmissions.py                  (inside `pipeline`, pure stdlib)
        │  scans /input/static for resubmission_lineage-tagged reports,
        │  runs each through normalize.py + map_attck.py independently
        ▼
results/{family}/resubmitted/{sha256}/{iocs,attck}/
```

Each resubmitted file gets its **own** `attck_mapping.json` rather than
being merged into the parent sample's: a dropped payload's own
capabilities aren't evidence the *parent* binary performs those techniques,
and blending the two would misattribute confidence in
`pipeline/mapper/src/reconcile.py`'s cross-source model.

```bash
# 1. Queue dropped files from an already-run dynamic analysis (--task-id 2
#    resolves docker/cape/work/storage/analyses/2/reports/report.json)
python3 dynamic/scripts/parse_cape.py --task-id 2 --output dynamic/reports/roning/ \
    --resubmit-dir docker/resubmit_queue --family roning --verbose
# -> docker/resubmit_queue/manifest/{sha256}.json + artifacts/{sha256}
#    Executables/scripts are prioritized; RESUBMIT_MAX_ARTIFACTS (default 25,
#    also settable via --resubmit-max-artifacts) caps how many get queued
#    per run: safe to re-run later, already-queued files are skipped.

# 2. Static half: analyze each queued artifact, tag it with lineage
docker exec malwhere-static python3 /scripts/process_resubmissions.py --verbose
# -> static/reports/roning/{sha256}_static.json (already-analyzed files skipped)

# 3. Merge half: normalize + map ATT&CK for anything newly tagged
docker exec malwhere-pipeline python3 /app/process_resubmissions.py --verbose
# -> results/roning/resubmitted/{sha256}/iocs/normalized_iocs.json
# -> results/roning/resubmitted/{sha256}/attck/attck_mapping.json
```

Both halves respect `RESUBMIT_TIME_BUDGET_MIN` (default 45 minutes,
see the `static`/`pipeline` service `environment:` blocks), they stop
*starting* new files once the budget is spent rather than cutting one off
mid-analysis, so a run is safe to just re-invoke later to pick up where
it left off. `docker/resubmit_queue/` is gitignored (raw dropped-file
bytes, same reasoning as `docker/cape/work/storage/`).

Only *static* analysis runs on resubmitted files, they aren't themselves
detonated in CAPE, so `RESUBMIT_MAX_DEPTH` is reserved for a future
chained dynamic-resubmission loop and isn't consumed by any script yet.

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
Java runtime not found (TTY required: normal in headless mode)
```

---

## Stopping the Environment

```bash
# Stop everything safely (data preserved)
docker compose -f docker/docker-compose.yml --profile core --profile sandbox stop

# Stop core only
docker compose -f docker/docker-compose.yml --profile core stop

# DANGER: deletes all volumes and data
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
MISP must be reachable on host port 443 (container port 443, not remapped to something like 8443). The `MISP_BASEURL` env var is ignored if the internal port differs from the external port. The current mapping, `127.0.0.1:443:443`, satisfies this (host port is still 443, just bound to loopback only, see the next entry for why): don't change the port number, `443:443` on either side of the colon.

### `inetsim` and `misp` both want port 443
`inetsim` runs with `network_mode: host` and (by design) needs to be reachable from the guest VM, so it binds `service_bind_address` to the host's libvirt-bridge IP (narrowed from `0.0.0.0`, see `docker/inetsim/entrypoint.sh`). `misp`'s own port 443 is bound to `127.0.0.1` specifically (`docker-compose.yml`'s `misp` service), not the Docker-default `0.0.0.0`, for exactly this reason: a `0.0.0.0` bind on either service blocks *any* other bind on that port host-wide, so if either one goes back to binding all interfaces, they collide again and one of them fails to start (MISP errors with "address already in use"; `inetsim`'s own log shows `https_443_tcp - failed!` while its other services start fine). Both together were verified end to end with a real CAPE detonation to confirm the guest VM still reaches `inetsim` correctly on the narrower bind (same domains/IPs/signatures as before the fix).

### MISP's MySQL password drifts from `.env`
The `misp` MySQL user's actual password is set once, during `mysql_data`'s very first init, to whatever `MYSQL_PASSWORD` was *at that time*, it does not get updated on later container recreates just because `.env` changed. If MISP's logs show `ERROR 1045 (28000): Access denied for user 'misp'@'...'` in a loop (`docker logs malwhere-misp`), that's this, the password baked into the volume no longer matches `.env`. Fix directly against MySQL:
```bash
docker exec malwhere-mysql mysql -uroot -p"$MYSQL_ROOT_PASSWORD" \
  -e "ALTER USER 'misp'@'%' IDENTIFIED BY '$MYSQL_PASSWORD'; FLUSH PRIVILEGES;"
docker restart malwhere-misp
```

### MISP web UI login doesn't match `.env`
Related to the above but separate: the real bootstrap admin account is `admin@admin.test`, not the `MISP_EMAIL` value in docker-compose.yml, and `MISP_PASSWORD`/`MISP_ADMIN_PASSWORD` doesn't reliably apply to it either. See the MISP login gotcha under Service Access above for the reset commands.

### `redis` needs to be running before `misp` starts
MISP uses `redis` for session storage: if it's down, MISP's web/API layer fails on *every* request (including pure API calls) with a misleading "Authentication failed" error that has nothing to do with the API key. `docker-compose.yml`'s `misp` service now has `depends_on: redis` with a healthcheck, so a fresh `docker compose up` won't hit this: but if you ever stop `redis` manually while `misp` keeps running, you'll need to restart `misp` too, not just `redis`.

### Static container build fails on apt (expired keys, unrelated third-party repos)
Historically this base image was `remnux/remnux-distro:focal` rather than plain `ubuntu:20.04`; that image bundles a dozen+ third-party apt repos for tools this Dockerfile never used, and being an infrequently-rebuilt frozen tag, their signing keys (and eventually the archive's own frozen keyring) expire, breaking `apt-get update` for all of them at once with no fix available except waiting for upstream. Fixed by moving to plain `ubuntu:20.04` — confirmed nothing here actually needs REMnux-specific tooling. If you still have a local image built from the old base, `docker compose build static` picks up the new one.

### Containers not stopping with `docker compose stop`
Always include the same `--profile` flags used at startup. Without them, Docker Compose cannot resolve which containers belong to the current configuration.

### CAPE build fails with "poetry: not found" or "CAPEv2/installer not found"
Both fixed in our fork ([z0ltrak/kvm-cape-docker](https://github.com/z0ltrak/kvm-cape-docker), `kvm` branch) -- see [Building the CAPE Image](#building-the-cape-image-required-first-step) above. If you're building from upstream `celyrin/cape-docker` instead, see the Troubleshooting subsection there for the manual fixes.

---

## Acknowledgements

This project uses the [cape-docker](https://github.com/celyrin/cape-docker) repository by [celyrin](https://github.com/celyrin) for CAPE sandbox containerization. We build from our own fork, [z0ltrak/kvm-cape-docker](https://github.com/z0ltrak/kvm-cape-docker) (`kvm` branch), which fixes two build failures we hit on a second machine (an uninitialized CAPEv2 submodule, and a flaky poetry install) on top of celyrin's KVM-compatible setup. We are grateful for their work in making CAPE deployment easier.

---

## License

This project is part of the TFM 2025-2026 at Universidad Complutense de Madrid. All rights reserved.
