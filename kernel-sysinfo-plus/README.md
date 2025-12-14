# sysinfo_plus kernel module

A production-style demo module that periodically captures system info and exposes it through procfs, sysfs, and a character device. Safe to load/unload and easy to test.

## Features
- Timer-based snapshots of memory, load averages, CPU count, and uptime.
- `/proc/sysinfo_plus` text view (seq_file).
- `/sys/kernel/sysinfo_plus/{log_level,interval,last_snapshot,logs_count}` tunables/metrics.
- `/dev/sysinfo_plus` character device emits the latest snapshot as JSON.
- `ioctl` (`_IO('s',1)`) to trigger an immediate snapshot.
- Module parameters: `interval_sec` (seconds), `log_level` (0/1).

## Build
```
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r) -y
make
```

### Build in Docker (no module load inside container)
```
docker build -t sysinfo-plus:latest kernel-sysinfo-plus
docker run --rm sysinfo-plus:latest ls -lh /build/sysinfo_plus/sysinfo_plus.ko
```

The Docker image installs headers matching the host kernel inside the container and runs `make` during build.

## Load
```
sudo insmod sysinfo_plus.ko interval_sec=3 log_level=1
```

## Inspect
```
dmesg | tail -n 20
cat /proc/sysinfo_plus
cat /sys/kernel/sysinfo_plus/last_snapshot
cat /sys/kernel/sysinfo_plus/logs_count
cat /sys/kernel/sysinfo_plus/interval
echo 10 | sudo tee /sys/kernel/sysinfo_plus/interval
cat /dev/sysinfo_plus
```

## Trigger snapshot via ioctl (C example)
```c
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    int fd = open("/dev/sysinfo_plus", O_RDONLY);
    if (fd < 0)
        return 1;
    ioctl(fd, _IO('s', 1));
    close(fd);
    return 0;
}
```

## Unload
```
sudo rmmod sysinfo_plus
sudo dmesg | tail
```

## CI
GitHub Actions workflow `.github/workflows/build.yml` builds the module on Ubuntu runners and also exercises the Docker build to ensure reproducibility.
