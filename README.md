# Linux System Health Checks

Improved health check scripts for Linux systems.

**Disclaimer**: This code was built with `Claude Opus 4.1` and `ChatGPT 5`.

## Scripts

**1. Memory Health Check (`mem_health_check.py`)**

Memory monitoring with PSI awareness, NUMA support, and container detection.

**2. CPU Health Check (`cpu_health_check.py`)**

CPU monitoring with steal time analysis and hypervisor detection.

**3. Disk Health Check (`disk_health_check.py`)**

Disk space and inode monitoring with container support and log rotation analysis.

## Features

* **High Performance**: Optimized for minimal overhead (can run every second)
* **Multiple Output Formats**: Icinga, Nagios, Prometheus, Zabbix, Checkmk, raw JSON
* **Container Aware**: Docker, Podman, Kubernetes support
* **VM Optimized**: Hypervisor detection and steal time analysis
* **Comprehensive Metrics**: PSI, NUMA, inodes, steal time, fragmentation
* **Self-Testing**: Built-in validation and performance testing

## Installation

```bash
git clone https://github.com/randombitsof0/linux-monitoring.git
cd linux-health-checks
chmod +x *.py
```

## Quick Start

### Memory Check

```bash
./mem_health_check.py --nagios
```

## CPU Check

```bash
./cpu_health_check.py --nagios
```
## Disk Check

```bash
./disk_health_check.py --full-analysis --check-inodes --check-docker
```

## Integration examples

### Icinga/Nagios configuration

```bash
# Command definition
define command {
    command_name check_memory
    command_line /opt/scripts/mem_health_check.py --nagios
}

define command {
    command_name check_cpu
    command_line /opt/scripts/cpu_health_check.py --nagios
}

define command {
    command_name check_disk
    command_line /opt/scripts/disk_health_check.py --nagios --check-inodes
}

# Service definitions
define service {
    use generic-service
    host_name linux-server
    service_description Memory Health
    check_command check_memory
}

define service {
    use generic-service
    host_name linux-server
    service_description CPU Health
    check_command check_cpu
}

define service {
    use generic-service
    host_name linux-server
    service_description Disk Health
    check_command check_disk
}
```

**Zabbix configuration**

```bash
# UserParameter definitions in zabbix_agentd.conf
UserParameter=memory.health[*], /opt/scripts/mem_health_check.py --zabbix
UserParameter=cpu.health[*], /opt/scripts/cpu_health_check.py --zabbix
UserParameter=disk.health[*], /opt/scripts/disk_health_check.py --zabbix

# Use with low-level discovery
UserParameter=disk.filesystems[*], /opt/scripts/disk_health_check.py --zabbix --basic
```

**Prometheus configuration**

```bash
# prometheus.yml scrape config
scrape_configs:
  - job_name: 'linux_health'
    static_configs:
      - targets: ['localhost:9100']  # node_exporter
    metrics_path: /custom_metrics
    static_configs:
      - targets: ['localhost']
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9115  # script exporter

# Use with script_exporter or textfile collector
# Create cron job to output metrics:
*/15 * * * * /opt/scripts/mem_health_check.py --prom > /var/lib/node_exporter/memory_health.prom
```

### Systemd Service example

```bash
# /etc/systemd/system/health-check.service
[Unit]
Description=System Health Checks
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/scripts/mem_health_check.py --nagios
ExecStart=/opt/scripts/cpu_health_check.py --nagios
ExecStart=/opt/scripts/disk_health_check.py --nagios
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

## Configuration examples

### Custom Thresholds

```bash
# Memory with custom thresholds
./mem_health_check.py --mem-warn 15 --mem-crit 5 --psi10-warn 15 --psi10-crit 25

# Disk with mount-specific thresholds
./disk_health_check.py -t "/:85%:95%" -t "/var:80%:90%" -t "/boot:200MB:100MB"

# CPU with VM-adjusted thresholds
./cpu_health_check.py --cpu-warn 75 --cpu-crit 90 --vm-auto-adjust
```

### High-Frequency monitoring

```bash
# Minimal overhead for frequent checks
./mem_health_check.py --high-freq --no-lock --raw
./cpu_health_check.py --high-freq --no-lock --raw
./disk_health_check.py --basic --high-freq --no-lock
```

### Container Environments

```bash
# Full container stack analysis
./disk_health_check.py --check-docker --check-podman --find-dangling
./mem_health_check.py --find-offender --offender-threshold 10240
```

## Metrics Collected

### Memory Health Check

* Memory available percentage
* PSI (Pressure Stall Information) metrics
* Swap activity rates
* NUMA node balance
* Memory fragmentation
* Container memory limits

### CPU Health Check

* CPU usage percentage
* CPU steal time (for VMs)
* Load averages
* CPU PSI metrics
* Hypervisor detection
* vCPU allocation

### Disk Health Check

* Disk space usage
* Inode usage with deep analysis
* ZFS/Btrfs dataset metrics
* Container image and volume analysis
* Log rotation status
* Hidden mountpoint detection

##  Self-Testing

```bash
# Validate all scripts
./mem_health_check.py --self-test
./cpu_health_check.py --self-test
./disk_health_check.py --self-test

# Debug output
./mem_health_check.py --debug --nagios
```

## License

MIT License - see LICENSE file for details.

## Contributing

* Fork the repository
* Create a feature branch
* Commit your changes
* Push to the branch
* Create a Pull Request

## Support

* Check the self-test functionality
* Review debug output with --debug flag
* Check system requirements and dependencies

**Note**: These scripts require Python 3.6+ and are tested on RHEL 7+, Ubuntu 18.04+, and other modern Linux distributions. On RHEL8, you may need to use `/usr/libexec/platform-python`
