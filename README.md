# Linux-Module

This repo contains a production-style kernel module example in `kernel-sysinfo-plus/`.

Key features:
- Timer-based snapshots of system info (RAM, load averages, CPUs, uptime).
- Interfaces: `/proc/sysinfo_plus`, `/sys/kernel/sysinfo_plus/*`, and `/dev/sysinfo_plus` (JSON output + ioctl trigger).
- Safe init/exit, module params, locking, and cleanup.
- Dockerfile to build the module in-container.
- GitHub Actions workflow to build on runners and to validate the Docker image.

See `kernel-sysinfo-plus/README.md` for build, Docker, load, and test steps.