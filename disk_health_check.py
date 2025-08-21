#!/usr/bin/env python3
"""
Disk Health Check — Linux disk space and inode health check

Purpose
-------
Comprehensive disk monitoring with inode analysis, container support (Docker/Podman/K8s),
hidden mountpoint detection, log rotation verification, and process/application attribution.

Supported Platforms
-------------------
* RHEL 7, 8, 9, 10
* Ubuntu 18.04+
* Kubernetes nodes (kubelet monitoring)
* Container hosts (Docker/Podman/Containerd)
* VMs and physical servers
* ZFS and Btrfs filesystems

Version: 1.0.0
License: MIT
"""

import argparse
import concurrent.futures
import fcntl
import glob
import json
import os
import pwd
import re
import signal
import subprocess
import sys
import time
from collections import defaultdict, namedtuple
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple, List, Optional, Union
from fnmatch import fnmatch
from shutil import which

# Exit codes following Nagios/Icinga plugin standards
EXIT_OK, EXIT_WARN, EXIT_CRIT, EXIT_UNK = 0, 1, 2, 3

# Default file paths (using tmpfs for performance)
STATE_DEFAULT = "/dev/shm/disk_health_check.state"
LOCK_DEFAULT  = "/dev/shm/disk_health_check.lock"
HIST_DEFAULT  = "/var/tmp/disk_health_check.history.jsonl"

# Version information
__version__ = "1.0.0"

# Default exclude patterns for dynamic/virtual filesystems (glob-aware)
DEFAULT_EXCLUDES = [
    '/proc*', '/sys*', '/dev/pts*', '/run*', '/dev/shm*',
    '/var/lib/docker/overlay2/*/merged',
    '/var/lib/containers/storage/overlay/*/merged',
    '/snap*', '/tmp/.mount_*'
]

# Filesystem types to skip by default (virtual/pseudo filesystems)
SKIP_FS_TYPES = [
    'tmpfs', 'devtmpfs', 'devpts', 'proc', 'sysfs', 'securityfs', 'selinuxfs', 'cgroup',
    'cgroup2', 'debugfs', 'tracefs', 'fusectl', 'hugetlbfs', 'mqueue',
    'binfmt_misc', 'configfs', 'pstore', 'autofs', 'squashfs',
    'efivarfs', 'bpf', 'nsfs', 'ramfs', 'rpc_pipefs'
]

# Known log file patterns
LOG_PATTERNS = [
    '/var/log/*.log',
    '/var/log/*/*.log',
    '/var/log/messages*',
    '/var/log/syslog*',
    '/var/log/journal/*'
]

# Performance tuning
MAX_PARALLEL_FS_CHECKS = 10  # Max concurrent filesystem checks
PROCESS_SCAN_CACHE_TTL = 300  # Cache process scans for 5 minutes
NFS_TIMEOUT = 2  # Timeout for NFS operations

# Threshold type
ThresholdSpec = namedtuple('ThresholdSpec', ['pattern', 'warn_type', 'warn_val', 'crit_type', 'crit_val'])

# ---------------------------------------------------------------------------
# ENHANCED CACHING SYSTEM
# ---------------------------------------------------------------------------

class Cache:
    """Thread-safe cache with TTL support and size limits."""
    def __init__(self, ttl: int = 60, max_size: int = 1000):
        self.ttl = ttl
        self.max_size = max_size
        self.data: Dict[str, Any] = {}
        self.timestamps: Dict[str, float] = {}
        self.access_count: Dict[str, int] = {}

    def get(self, key: str, generator=None, *args, **kwargs):
        now = time.time()
        if key in self.data and now - self.timestamps[key] < self.ttl:
            self.access_count[key] = self.access_count.get(key, 0) + 1
            return self.data[key]
        if generator:
            value = generator(*args, **kwargs)
            self.set(key, value)
            return value
        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        if len(self.data) >= self.max_size and key not in self.data:
            if self.access_count:
                evict_key = min(self.access_count, key=self.access_count.get)
                for d in (self.data, self.timestamps, self.access_count):
                    d.pop(evict_key, None)
        self.data[key] = value
        self.timestamps[key] = time.time()
        self.access_count[key] = 0
        if ttl is not None:
            # fake the timestamp so remaining TTL ~= given ttl
            self.timestamps[key] = time.time() - (self.ttl - ttl)

    def clear(self):
        self.data.clear()
        self.timestamps.clear()
        self.access_count.clear()

_cache = Cache(ttl=60, max_size=1000)

# ---------------------------------------------------------------------------
# SIGNAL HANDLING
# ---------------------------------------------------------------------------

class GracefulExit:
    """Handle SIGTERM/SIGINT for clean shutdown."""
    def __init__(self):
        self.exit_now = False
        signal.signal(signal.SIGTERM, self.handle_signal)
        signal.signal(signal.SIGINT, self.handle_signal)

    def handle_signal(self, signum, frame):
        self.exit_now = True

# ---------------------------------------------------------------------------
# UTILITY FUNCTIONS
# ---------------------------------------------------------------------------

def flock_nowait(path: str) -> Optional[int]:
    """Acquire non-blocking exclusive lock."""
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except OSError:
        return None

def run_command(cmd: List[str], timeout: int = 5, check_stale_nfs: bool = False) -> Tuple[int, str, str]:
    """Run command with timeout and optional NFS stale check."""
    if check_stale_nfs:
        timeout = min(timeout, NFS_TIMEOUT)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, 'LANG': 'C', 'LC_ALL': 'C'}
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)

def human_to_bytes(size_str: str) -> int:
    """Convert human-readable size to bytes (supports decimal and binary)."""
    s = size_str.upper().strip()
    if s.isdigit():
        return int(s)
    m = re.match(r'^([\d.]+)\s*([KMGTPE])(I)?B?$', s)
    if not m:
        return 0
    size = float(m.group(1))
    unit = m.group(2)
    binary = m.group(3) == 'I'
    units = {'K': (1024 if binary else 1000),
             'M': (1024**2 if binary else 1000**2),
             'G': (1024**3 if binary else 1000**3),
             'T': (1024**4 if binary else 1000**4),
             'P': (1024**5 if binary else 1000**5),
             'E': (1024**6 if binary else 1000**6)}
    return int(size * units.get(unit, 1))

def bytes_to_human(size: int, binary: bool = True) -> str:
    """Convert bytes to human-readable format."""
    if binary:
        divisor = 1024.0
        units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB']
    else:
        divisor = 1000.0
        units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB']
    value = float(size)
    for unit in units:
        if value < divisor:
            return f"{value:.1f}{unit}"
        value /= divisor
    return f"{value:.1f}{units[-1]}"

def prom_escape(s: str) -> str:
    """Escape a string for use as a Prometheus label value."""
    return s.replace("\\", "\\\\").replace("\"", "\\\"")

def parse_threshold_value(val: str) -> Tuple[str, Union[float, int]]:
    """Parse threshold value - supports percentages and byte sizes."""
    val = val.strip()
    if val.endswith('%'):
        return 'percent', float(val[:-1])
    return 'bytes', human_to_bytes(val)

# ---------------------------------------------------------------------------
# ADVANCED FILESYSTEM DETECTION
# ---------------------------------------------------------------------------

def _pick_cmd(name: str, fallbacks: List[str]) -> Optional[str]:
    p = which(name)
    if p:
        return p
    for fb in fallbacks:
        if os.path.exists(fb):
            return fb
    return None

def detect_zfs_datasets() -> List[Dict[str, Any]]:
    """Detect ZFS datasets and their properties."""
    datasets = []
    zfs_bin = _pick_cmd('zfs', ['/usr/sbin/zfs', '/sbin/zfs'])
    if not zfs_bin:
        return datasets
    try:
        cmd = [zfs_bin, 'list', '-H', '-o',
               'name,used,avail,refer,mountpoint,compression,compressratio']
        rc, out, _ = run_command(cmd, timeout=5)
        if rc == 0:
            for line in out.strip().split('\n'):
                if not line:
                    continue
                parts = line.split('\t')
                if len(parts) >= 7:
                    datasets.append({
                        'name': parts[0],
                        'used': human_to_bytes(parts[1]),
                        'available': human_to_bytes(parts[2]),
                        'referenced': human_to_bytes(parts[3]),
                        'mountpoint': parts[4],
                        'compression': parts[5],
                        'compressratio': parts[6],
                        'type': 'zfs'
                    })
    except Exception:
        pass
    return datasets

def detect_btrfs_subvolumes() -> List[Dict[str, Any]]:
    """Detect Btrfs subvolumes and snapshots."""
    subvolumes = []
    btrfs_bin = _pick_cmd('btrfs', ['/usr/sbin/btrfs', '/sbin/btrfs'])
    findmnt_bin = _pick_cmd('findmnt', ['/usr/bin/findmnt', '/bin/findmnt'])
    if not btrfs_bin or not findmnt_bin:
        return subvolumes
    try:
        rc, out, _ = run_command([findmnt_bin, '-t', 'btrfs', '-n', '-o', 'TARGET'], timeout=5)
        if rc == 0:
            for mountpoint in out.strip().split('\n'):
                if not mountpoint:
                    continue
                rc2, out2, _ = run_command([btrfs_bin, 'subvolume', 'list', mountpoint], timeout=5)
                if rc2 == 0:
                    for line in out2.strip().split('\n'):
                        if 'path' in line:
                            parts = line.split()
                            if parts:
                                subvolumes.append({
                                    'mountpoint': mountpoint,
                                    'subvolume': parts[-1],
                                    'type': 'btrfs'
                                })
    except Exception:
        pass
    return subvolumes

# ---------------------------------------------------------------------------
# SYSTEMD JOURNAL MONITORING
# ---------------------------------------------------------------------------

def check_journal_usage() -> Dict[str, Any]:
    """Check systemd journal disk usage and configuration."""
    journal_info = {
        'available': False,
        'disk_usage': 0,
        'disk_usage_human': '0B',
        'max_size_configured': None,
        'vacuum_time': None,
        'issues': []
    }
    journal_path = '/var/log/journal'
    if not os.path.exists(journal_path):
        return journal_info
    journal_info['available'] = True
    try:
        rc, out, _ = run_command(['journalctl', '--disk-usage'], timeout=5)
        if rc == 0:
            # handle: "take up XXX on disk" or "take up XXX in the file system"
            m = re.search(r'take up\s+([\d.]+\s*[KMGT]?I?B?)\s+(on disk|in (the )?file system)', out, re.I)
            if m:
                size_str = m.group(1)
                journal_info['disk_usage'] = human_to_bytes(size_str)
                journal_info['disk_usage_human'] = bytes_to_human(journal_info['disk_usage'])
        # journald.conf and drop-ins
        cfgs = ['/etc/systemd/journald.conf'] + sorted(glob.glob('/etc/systemd/journald.conf.d/*.conf'))
        for cfg in cfgs:
            if not os.path.exists(cfg):
                continue
            try:
                with open(cfg, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        if line.startswith('SystemMaxUse='):
                            journal_info['max_size_configured'] = line.split('=', 1)[1].strip()
                        elif line.startswith('MaxRetentionSec='):
                            journal_info['vacuum_time'] = line.split('=', 1)[1].strip()
            except Exception:
                continue
        if journal_info['disk_usage'] > 1024**3 and not journal_info['max_size_configured']:
            journal_info['issues'].append(
                f"Journal using {journal_info['disk_usage_human']} without SystemMaxUse configured"
            )
    except Exception:
        pass
    return journal_info

# ---------------------------------------------------------------------------
# ENHANCED INODE ANALYSIS
# ---------------------------------------------------------------------------

def get_inode_usage_by_directory(path: str, top_n: int = 10) -> List[Dict[str, Any]]:
    """Get inode usage by directory with improved performance."""
    cache_key = f"inode_dirs_{path}_{top_n}"
    cached = _cache.get(cache_key)
    if cached:
        return cached
    try:
        cmd = f"""
        find {path} -xdev -type d -print0 2>/dev/null | \
        xargs -0 -P4 -I{{}} sh -c 'echo $(find "{{}}" -maxdepth 1 -type f 2>/dev/null | wc -l) "{{}}"' | \
        sort -rn | head -{top_n}
        """
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        dirs = []
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                try:
                    count = int(parts[0])
                except ValueError:
                    continue
                dirs.append({'path': parts[1], 'inode_count': count})
        _cache.set(cache_key, dirs, ttl=60)
        return dirs
    except Exception:
        return []

def find_inode_consumers_by_process() -> Dict[str, Dict[str, Any]]:
    """Find processes with many open files - rate limited."""
    cache_key = "process_inode_consumers"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached
    process_inodes: Dict[str, Dict[str, Any]] = {}
    try:
        cmd = """
        for pid in /proc/[0-9]*; do
            [ -d "$pid/fd" ] && echo "$(ls "$pid"/fd 2>/dev/null | wc -l) $(basename "$pid")";
        done | sort -rn | head -20
        """
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        top_pids = []
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split()
            if len(parts) == 2:
                try:
                    if int(parts[0]) > 10:
                        top_pids.append(parts[1])
                except ValueError:
                    continue
        for pid in top_pids:
            pid_dir = f'/proc/{pid}'
            try:
                with open(f'{pid_dir}/comm', 'r') as f:
                    comm = f.read().strip()
                fd_dir = f'{pid_dir}/fd'
                fd_count = len(os.listdir(fd_dir)) if os.path.isdir(fd_dir) else 0
                stat_info = os.stat(pid_dir)
                try:
                    owner = pwd.getpwuid(stat_info.st_uid).pw_name
                except Exception:
                    owner = str(stat_info.st_uid)
                try:
                    cwd = os.readlink(f'{pid_dir}/cwd')
                except Exception:
                    cwd = 'unknown'
                info = process_inodes.setdefault(comm, {
                    'total_fds': 0,
                    'processes': [],
                    'owners': set(),
                    'working_dirs': set(),
                })
                info['total_fds'] += fd_count
                info['processes'].append({'pid': pid, 'fd_count': fd_count})
                info['owners'].add(owner)
                if cwd != 'unknown':
                    info['working_dirs'].add(cwd)
            except Exception:
                continue
    except Exception:
        pass
    for comm in list(process_inodes.keys()):
        process_inodes[comm]['owners'] = list(process_inodes[comm]['owners'])
        process_inodes[comm]['working_dirs'] = list(process_inodes[comm]['working_dirs'])
    _cache.set(cache_key, process_inodes, ttl=PROCESS_SCAN_CACHE_TTL)
    return process_inodes

# ---------------------------------------------------------------------------
# PARALLEL FILESYSTEM CHECKING
# ---------------------------------------------------------------------------

def check_filesystem_parallel(mountpoint: str, mount_info: Dict[str, str],
                              exclude_patterns: List[str]) -> Optional[Dict[str, Any]]:
    """Check a single filesystem - designed for parallel execution."""
    try:
        is_network = mount_info['fstype'] in ['nfs', 'nfs4', 'cifs', 'smbfs']
        if is_network:
            try:
                result = subprocess.run(
                    ['stat', '-f', mountpoint],
                    timeout=NFS_TIMEOUT,
                    capture_output=True
                )
                if result.returncode != 0:
                    return None
            except subprocess.TimeoutExpired:
                return {
                    'device': mount_info['device'],
                    'mountpoint': mountpoint,
                    'fstype': mount_info['fstype'],
                    'error': 'Stale mount (timeout)',
                    'stale': True
                }
        stat = os.statvfs(mountpoint)
        total = stat.f_blocks * stat.f_frsize
        if total <= 0:
            return None
        free = stat.f_bavail * stat.f_frsize
        used = (stat.f_blocks - stat.f_bfree) * stat.f_frsize
        use_percent = (used / total) * 100.0
        total_inodes = stat.f_files
        used_inodes = (stat.f_files - stat.f_ffree) if stat.f_files > 0 else 0
        free_inodes = stat.f_favail if stat.f_files > 0 else 0
        inode_percent = (used_inodes / total_inodes) * 100.0 if total_inodes > 0 else 0.0
        fs_info: Dict[str, Any] = {
            'device': mount_info['device'],
            'mountpoint': mountpoint,
            'fstype': mount_info['fstype'],
            'total': total,
            'used': used,
            'available': free,
            'use_percent': round(use_percent, 2),
            'total_inodes': int(total_inodes),
            'used_inodes': int(used_inodes),
            'free_inodes': int(free_inodes),
            'inode_percent': round(inode_percent, 2),
        }
        if inode_percent > 50.0:
            fs_info['inode_analysis'] = {
                'top_dirs': get_inode_usage_by_directory(mountpoint, 5),
                'creation_rate': analyze_inode_creation_rate(mountpoint),
            }
        return fs_info
    except Exception as e:
        return {
            'device': mount_info['device'],
            'mountpoint': mountpoint,
            'fstype': mount_info['fstype'],
            'error': str(e)
        }

def get_filesystems_advanced(exclude_patterns: List[str], include_remote: bool = False) -> List[Dict[str, Any]]:
    """Gather filesystem usage with parallel checking for better performance."""
    mounts: Dict[str, Dict[str, str]] = {}
    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                device, mountpoint, fstype = parts[:3]
                if fstype in SKIP_FS_TYPES:
                    continue
                if fstype == 'overlay':
                    overlay_skip = [
                        '/var/lib/docker/overlay2/*/merged',
                        '/var/lib/containers/storage/overlay/*/merged'
                    ]
                    if any(fnmatch(mountpoint, g) for g in overlay_skip):
                        continue
                if not include_remote and fstype in ['nfs', 'nfs4', 'cifs', 'smbfs']:
                    continue
                if any(fnmatch(mountpoint, pattern) for pattern in exclude_patterns):
                    continue
                mounts[mountpoint] = {'device': device, 'fstype': fstype}
    except Exception:
        return []
    filesystems = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PARALLEL_FS_CHECKS) as executor:
        futures = {
            executor.submit(check_filesystem_parallel, mp, info, exclude_patterns): mp
            for mp, info in mounts.items()
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result and 'error' not in result:
                filesystems.append(result)
            elif result and 'stale' in result:
                filesystems.append(result)
    return filesystems

def analyze_inode_creation_rate(mountpoint: str) -> Dict[str, Any]:
    """Estimate inode creation rate with caching."""
    cache_key = f"inode_rate_{mountpoint}"
    cached = _cache.get(cache_key)
    if cached:
        return cached
    watch_dirs = ['/tmp', '/var/tmp', '/var/spool', '/var/cache', '/var/log']
    results: Dict[str, Any] = {}
    for d in watch_dirs:
        full = os.path.join(mountpoint, d.lstrip('/'))
        if os.path.exists(full):
            try:
                cmd = f"find {full} -type f -cmin -60 2>/dev/null | wc -l"
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    recent = int(r.stdout.strip() or '0')
                    if recent > 100:
                        results[d] = {'recent_files': recent, 'rate_per_hour': recent}
            except Exception:
                continue
    _cache.set(cache_key, results, ttl=300)
    return results

# ---------------------------------------------------------------------------
# ENHANCED CONTAINER RUNTIME SUPPORT
# ---------------------------------------------------------------------------

class ContainerRuntime:
    """Unified interface for container runtimes with enhanced detection."""
    @staticmethod
    def detect_runtimes() -> Dict[str, str]:
        runtimes: Dict[str, str] = {}
        runtime_checks = [
            ('docker', ['/usr/bin/docker', '/usr/local/bin/docker']),
            ('podman', ['/usr/bin/podman', '/usr/local/bin/podman']),
            ('containerd', ['/usr/bin/ctr', '/usr/local/bin/ctr']),
            ('crictl', ['/usr/bin/crictl', '/usr/local/bin/crictl']),
            ('nerdctl', ['/usr/bin/nerdctl', '/usr/local/bin/nerdctl']),
            ('crio', ['/usr/bin/crio', '/usr/local/bin/crio']),
        ]
        for runtime, paths in runtime_checks:
            for path in paths:
                if os.path.exists(path):
                    runtimes[runtime] = path
                    break
        return runtimes

    @staticmethod
    def get_all_container_stats(runtimes: Dict[str, str]) -> Dict[str, Any]:
        stats = {
            'total_images': 0,
            'total_containers': 0,
            'total_volumes': 0,
            'dangling_images': [],
            'unused_volumes': [],
            'total_size': 0,
            'runtimes_found': list(runtimes.keys())
        }
        for runtime, path in runtimes.items():
            if runtime in ['docker', 'podman']:
                rc, out, _ = run_command([path, 'images', '-q'], timeout=5)
                if rc == 0 and out.strip():
                    stats['total_images'] += len(out.strip().splitlines())
                rc, out, _ = run_command([path, 'ps', '-aq'], timeout=5)
                if rc == 0 and out.strip():
                    stats['total_containers'] += len(out.strip().splitlines())
                rc, out, _ = run_command([path, 'images', '-f', 'dangling=true', '-q'], timeout=5)
                if rc == 0 and out.strip():
                    stats['dangling_images'].extend(out.strip().splitlines())
        return stats

# ---------------------------------------------------------------------------
# THRESHOLD PARSING WITH BYTE SUPPORT
# ---------------------------------------------------------------------------

def parse_thresholds(threshold_args: Optional[List[str]],
                     default_warn: str,
                     default_crit: str) -> List[ThresholdSpec]:
    """Parse threshold specifications supporting both percentage and byte values."""
    rules: List[ThresholdSpec] = []
    if threshold_args:
        for entry in threshold_args:
            try:
                parts = entry.split(':', 2)
                if len(parts) == 3:
                    pattern = parts[0]
                    warn_type, warn_val = parse_threshold_value(parts[1])
                    crit_type, crit_val = parse_threshold_value(parts[2])
                    rules.append(ThresholdSpec(pattern, warn_type, warn_val, crit_type, crit_val))
            except ValueError:
                continue
    def_warn_type, def_warn_val = parse_threshold_value(default_warn)
    def_crit_type, def_crit_val = parse_threshold_value(default_crit)
    rules.append(ThresholdSpec('*', def_warn_type, def_warn_val, def_crit_type, def_crit_val))
    return rules

def evaluate_threshold(value_used: float, total: float,
                       threshold_type: str, threshold_val: Union[float, int]) -> bool:
    """Return True if threshold is exceeded."""
    if total <= 0:
        return False
    if threshold_type == 'percent':
        return (value_used / total * 100.0) >= float(threshold_val)
    # bytes: warn/crit express MIN FREE bytes allowed
    available = total - value_used
    return available <= int(threshold_val)

def select_thresholds_for_mount(mountpoint: str, rules: List[ThresholdSpec]) -> ThresholdSpec:
    """Select the best matching threshold rule for a mountpoint (last match wins)."""
    selected = rules[-1]
    for rule in rules:
        if fnmatch(mountpoint, rule.pattern):
            selected = rule
    return selected

# ---------------------------------------------------------------------------
# LOG ROTATION ANALYSIS WITH IMPROVEMENTS
# ---------------------------------------------------------------------------

def check_log_rotation() -> Dict[str, Any]:
    """Enhanced log rotation check with systemd journal support."""
    status = {
        'logrotate_configured': False,
        'logrotate_config_files': [],
        'compression_enabled': False,
        'last_rotation': None,
        'large_logs': [],
        'uncompressed_old_logs': [],
        'issues': [],
        'journal': None
    }
    status['journal'] = check_journal_usage()
    if status['journal']['issues']:
        status['issues'].extend(status['journal']['issues'])
    logrotate_path = None
    for p in ['/usr/sbin/logrotate', '/sbin/logrotate']:
        if os.path.exists(p):
            logrotate_path = p
            status['logrotate_configured'] = True
            break
    if not logrotate_path:
        status['issues'].append('logrotate not installed')
        return status
    for pattern in ['/etc/logrotate.conf', '/etc/logrotate.d/*']:
        for cfg in glob.glob(pattern):
            if os.path.isfile(cfg):
                status['logrotate_config_files'].append(cfg)
                try:
                    with open(cfg, 'r') as f:
                        content = f.read()
                        if 'compress' in content and 'nocompress' not in content:
                            status['compression_enabled'] = True
                except Exception:
                    pass
    st_file = '/var/lib/logrotate/logrotate.status'
    if os.path.exists(st_file):
        try:
            st = os.stat(st_file)
            last = datetime.fromtimestamp(st.st_mtime)
            status['last_rotation'] = last.isoformat()
            days_since = (datetime.now() - last).days
            if days_since > 2:
                status['issues'].append(f'No rotation for {days_since} days')
        except Exception:
            pass
    for pattern in LOG_PATTERNS:
        for lf in glob.glob(pattern):
            try:
                if not os.path.isfile(lf):
                    continue
                size = os.path.getsize(lf)
                if size > 100 * 1024 * 1024:
                    status['large_logs'].append({
                        'path': lf,
                        'size': size,
                        'size_human': bytes_to_human(size)
                    })
                if any(x in lf for x in ['.1', '.2', '.3']) and \
                   not any(lf.endswith(x) for x in ['.gz', '.bz2', '.xz', '.zst']):
                    if size > 10 * 1024 * 1024:
                        status['uncompressed_old_logs'].append({
                            'path': lf,
                            'size': size,
                            'size_human': bytes_to_human(size)
                        })
            except Exception:
                continue
    if status['compression_enabled'] and status['uncompressed_old_logs']:
        status['issues'].append('Compression configured but old logs not compressed')
    return status

def identify_log_writers() -> Dict[str, List[Dict[str, Any]]]:
    """Identify processes writing to logs - cached for performance."""
    cache_key = "log_writers"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached
    writers: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    try:
        rc, out, _ = run_command(['lsof', '+D', '/var/log', '-F', 'pn'], timeout=10)
        if rc == 0:
            current_pid = None
            for line in out.strip().split('\n'):
                if line.startswith('p'):
                    current_pid = line[1:]
                elif line.startswith('n') and current_pid:
                    lf = line[1:]
                    if lf.endswith('.log') or 'log' in lf:
                        try:
                            with open(f'/proc/{current_pid}/comm', 'r') as f:
                                comm = f.read().strip()
                            writers[lf].append({'pid': current_pid, 'process': comm})
                        except Exception:
                            pass
    except Exception:
        pass
    result = dict(writers)
    _cache.set(cache_key, result, ttl=60)
    return result

# ---------------------------------------------------------------------------
# HIDDEN MOUNTPOINT DETECTION
# ---------------------------------------------------------------------------

def detect_hidden_mountpoints() -> List[Dict[str, Any]]:
    """Detect space hidden under mountpoints - cached."""
    cache_key = "hidden_mountpoints"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached
    hidden: List[Dict[str, Any]] = []
    mountpoints = set()
    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    mountpoints.add(parts[1])
    except Exception:
        _cache.set(cache_key, hidden, ttl=300)
        return hidden
    for mp in mountpoints:
        if mp in ['/', '/proc', '/sys', '/dev']:
            continue
        try:
            temp_mount = f'/tmp/.hidden_check_{os.getpid()}'
            os.makedirs(temp_mount, exist_ok=True)
            parent = os.path.dirname(mp)
            base = os.path.basename(mp)
            rc, _, _ = run_command(['mount', '--bind', parent, temp_mount], timeout=2)
            if rc == 0:
                try:
                    check_path = os.path.join(temp_mount, base)
                    if os.path.exists(check_path):
                        rc2, out2, _ = run_command(['du', '-sb', check_path], timeout=5)
                        if rc2 == 0:
                            size = int(out2.split()[0])
                            if size > 1024 * 1024:
                                hidden.append({
                                    'mountpoint': mp,
                                    'hidden_size': size,
                                    'hidden_size_human': bytes_to_human(size)
                                })
                finally:
                    # best effort unmount
                    um = subprocess.run(['umount', temp_mount], timeout=2, capture_output=True)
                    if um.returncode != 0:
                        subprocess.run(['umount', '-l', temp_mount], timeout=2, capture_output=True)
            try:
                os.rmdir(temp_mount)
            except Exception:
                pass
        except Exception:
            continue
    _cache.set(cache_key, hidden, ttl=300)
    return hidden

# ---------------------------------------------------------------------------
# STATE MANAGEMENT
# ---------------------------------------------------------------------------

class StateManager:
    """Enhanced state management with compression support."""
    def __init__(self, path: str):
        self.path = path
        self._cache: Optional[Dict[str, Any]] = None
        self._cache_time = 0.0
        self._cache_ttl = 0.5

    def read(self) -> Dict[str, Any]:
        now = time.time()
        if self._cache and now - self._cache_time < self._cache_ttl:
            return self._cache
        try:
            with open(self.path, 'rb') as f:
                content = f.read()
                if len(content) > 10240:
                    try:
                        import gzip
                        content = gzip.decompress(content)
                    except Exception:
                        pass
                self._cache = json.loads(content)
                self._cache_time = now
                return self._cache
        except Exception:
            return {}

    def write(self, data: Dict[str, Any]):
        tmp = self.path + '.tmp'
        content = json.dumps(data, separators=(',', ':')).encode()
        if len(content) > 10240:
            try:
                import gzip
                content = gzip.compress(content, compresslevel=1)
            except Exception:
                pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, content)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.path)
        self._cache = data
        self._cache_time = time.time()

# ---------------------------------------------------------------------------
# MAIN MONITORING LOGIC
# ---------------------------------------------------------------------------

def parse_args():
    """Parse command-line arguments."""
    ap = argparse.ArgumentParser(
        description="Advanced disk space and inode health check v3.2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Basic check with byte-based thresholds\n"
            "  %(prog)s -t '/boot:200MB:100MB' -t '/var:80%%:90%%'\n\n"
            "  # Full analysis with all features\n"
            "  %(prog)s --full-analysis --check-inodes --check-docker\n\n"
            "  # High-frequency monitoring\n"
            "  %(prog)s --basic --high-freq --no-lock\n\n"
            "  # Container environment check\n"
            "  %(prog)s --check-docker --check-podman --find-dangling\n\n"
            "  # ZFS/Btrfs aware monitoring\n"
            "  %(prog)s --check-zfs --check-btrfs\n"
        ),
    )
    out = ap.add_argument_group('Output Formats')
    out.add_argument("--nagios", action="store_true", help="Nagios format (default)")
    out.add_argument("--zabbix", action="store_true", help="JSON for Zabbix")
    out.add_argument("--prom", action="store_true", help="Prometheus format")
    out.add_argument("--raw", action="store_true", help="Minimal JSON")
    lvl = ap.add_argument_group('Check Levels')
    lvl.add_argument("--basic", action="store_true", help="Basic checks only (fast, 1Hz capable)")
    lvl.add_argument("--full-analysis", action="store_true", help="Complete analysis (slower)")
    lvl.add_argument("--high-freq", action="store_true", help="Optimize for high-frequency execution")
    thr = ap.add_argument_group('Thresholds')
    thr.add_argument("-t", "--threshold", action="append",
                     help="Threshold: mount:warn:crit (e.g., /var:80%%:90%% or /boot:200MB:100MB)")
    thr.add_argument("--default-warn", default="80%", help="Default warning threshold")
    thr.add_argument("--default-crit", default="90%", help="Default critical threshold")
    thr.add_argument("--inode-warn", type=float, default=80.0, help="Inode usage warning %%")
    thr.add_argument("--inode-crit", type=float, default=90.0, help="Inode usage critical %%")
    feat = ap.add_argument_group('Features')
    feat.add_argument("--check-inodes", action="store_true", help="Advanced inode analysis")
    feat.add_argument("--check-docker", action="store_true", help="Check Docker")
    feat.add_argument("--check-podman", action="store_true", help="Check Podman")
    feat.add_argument("--check-k8s", action="store_true", help="Check Kubernetes")
    feat.add_argument("--check-zfs", action="store_true", help="Check ZFS datasets")
    feat.add_argument("--check-btrfs", action="store_true", help="Check Btrfs subvolumes")
    feat.add_argument("--find-dangling", action="store_true", help="Find dangling images/volumes")
    feat.add_argument("--check-hidden", action="store_true", help="Detect hidden mountpoint usage")
    feat.add_argument("--check-logs", action="store_true", help="Verify log rotation")
    feat.add_argument("--check-journal", action="store_true", help="Check systemd journal")
    feat.add_argument("--identify-processes", action="store_true", help="Identify problem processes")
    sel = ap.add_argument_group('Selection/Exclusions')
    sel.add_argument("-x", "--exclude", action="append", help="Exclude path pattern (glob)")
    sel.add_argument("--exclude-type", action="append", help="Exclude filesystem type")
    sel.add_argument("--include-remote", action="store_true", help="Include remote filesystems")
    det = ap.add_argument_group('Output Detail')
    det.add_argument("--perf-limit", type=int, default=20,
                     help="Max filesystems in perfdata (0=unlimited)")
    det.add_argument("--summary", type=int, default=3,
                     help="Top N fullest mounts in message")
    det.add_argument("--multiline", action="store_true",
                     help="Detailed multiline output")
    det.add_argument("--smart-perf", action="store_true",
                     help="Include only critical/warning filesystems in perfdata")
    perf = ap.add_argument_group('Performance')
    perf.add_argument("--no-lock", action="store_true", help="Skip locking")
    perf.add_argument("--cache-ttl", type=int, default=60, help="Cache TTL in seconds")
    perf.add_argument("--parallel", type=int, default=MAX_PARALLEL_FS_CHECKS,
                      help=f"Max parallel filesystem checks (default: {MAX_PARALLEL_FS_CHECKS})")
    paths = ap.add_argument_group('Files')
    paths.add_argument("--state-file", default=STATE_DEFAULT, help="State file path")
    paths.add_argument("--lock-file", default=LOCK_DEFAULT, help="Lock file path")
    util = ap.add_argument_group('Utility')
    util.add_argument("--self-test", action="store_true", help="Run self-test")
    util.add_argument("--list", action="store_true", help="List filesystems and exit")
    util.add_argument("--debug", action="store_true", help="Debug output")
    util.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap.parse_args()

def run_self_test() -> int:
    """Enhanced self-test."""
    print(f"Disk Health Check Self-Test v{__version__}")
    print("=" * 40)
    tests = []
    print("Testing filesystem detection...", end=" ")
    try:
        fs_list = get_filesystems_advanced(DEFAULT_EXCLUDES, include_remote=False)
        if fs_list:
            tests.append(("filesystems", f"OK ({len(fs_list)} found)"))
            print(f"OK ({len(fs_list)} filesystems)")
        else:
            tests.append(("filesystems", "FAIL: No filesystems"))
            print("FAIL")
    except Exception as e:
        tests.append(("filesystems", f"FAIL: {e}"))
        print(f"FAIL: {e}")
    print("Testing container runtime detection...", end=" ")
    runtimes = ContainerRuntime.detect_runtimes()
    if runtimes:
        runtime_str = ", ".join(runtimes.keys())
        tests.append(("containers", f"OK ({runtime_str})"))
        print(f"OK ({runtime_str})")
    else:
        tests.append(("containers", "None detected"))
        print("None detected")
    print("Testing ZFS detection...", end=" ")
    zfs_datasets = detect_zfs_datasets()
    if zfs_datasets:
        tests.append(("zfs", f"OK ({len(zfs_datasets)} datasets)"))
        print(f"OK ({len(zfs_datasets)} datasets)")
    else:
        tests.append(("zfs", "Not available"))
        print("Not available")
    print("Testing systemd journal...", end=" ")
    journal = check_journal_usage()
    if journal['available']:
        tests.append(("journal", f"OK ({journal['disk_usage_human']})"))
        print(f"OK ({journal['disk_usage_human']})")
    else:
        tests.append(("journal", "Not available"))
        print("Not available")
    print("Testing cache system...", end=" ")
    try:
        _cache.set("test", "value")
        tests.append(("cache", "OK" if _cache.get("test") == "value" else "FAIL"))
        print("OK" if _cache.get("test") == "value" else "FAIL")
    except Exception as e:
        tests.append(("cache", f"FAIL: {e}"))
        print(f"FAIL: {e}")
    print("\n" + "=" * 40)
    print("Test Summary:")
    for name, status in tests:
        print(f"  {name:15s}: {status}")
    print("=" * 40)
    critical_passed = any('OK' in t[1] for t in tests if t[0] == 'filesystems')
    print("✓ Core tests passed!" if critical_passed else "✗ Some tests failed")
    return EXIT_OK if critical_passed else EXIT_UNK

def perform_basic_checks(exclude_patterns: List[str], include_remote: bool) -> Dict[str, Any]:
    """Optimized basic checks for high-frequency monitoring."""
    results = {'filesystems': [], 'timestamp': time.time()}
    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                device, mountpoint, fstype = parts[:3]
                if fstype in SKIP_FS_TYPES:
                    continue
                if fstype == 'overlay':
                    overlay_skip = [
                        '/var/lib/docker/overlay2/*/merged',
                        '/var/lib/containers/storage/overlay/*/merged'
                    ]
                    if any(fnmatch(mountpoint, g) for g in overlay_skip):
                        continue
                if not include_remote and fstype in ['nfs', 'nfs4', 'cifs', 'smbfs']:
                    continue
                if any(fnmatch(mountpoint, ex) for ex in exclude_patterns):
                    continue
                try:
                    stat = os.statvfs(mountpoint)
                    total = stat.f_blocks * stat.f_frsize
                    if total <= 0:
                        continue
                    used = (stat.f_blocks - stat.f_bfree) * stat.f_frsize
                    use_percent = (used / total) * 100.0
                    inode_percent = 0.0
                    if stat.f_files > 0:
                        used_inodes = stat.f_files - stat.f_ffree
                        inode_percent = (used_inodes / stat.f_files) * 100.0
                    results['filesystems'].append({
                        'device': device,
                        'mountpoint': mountpoint,
                        'fstype': fstype,
                        'total': total,
                        'used': used,
                        'available': stat.f_bavail * stat.f_frsize,
                        'use_percent': round(use_percent, 2),
                        'inode_percent': round(inode_percent, 2),
                    })
                except Exception:
                    continue
    except Exception:
        pass
    return results

def perform_full_analysis(args, exclude_patterns: List[str]) -> Dict[str, Any]:
    """Complete analysis with all features enabled."""
    results: Dict[str, Any] = {
        'filesystems': [],
        'container_runtimes': {},
        'container_stats': {},
        'issues': [],
        'recommendations': [],
        'timestamp': time.time(),
    }
    global MAX_PARALLEL_FS_CHECKS
    MAX_PARALLEL_FS_CHECKS = args.parallel
    results['filesystems'] = get_filesystems_advanced(exclude_patterns, args.include_remote)
    if args.check_zfs:
        zfs_datasets = detect_zfs_datasets()
        if zfs_datasets:
            results['zfs_datasets'] = zfs_datasets
            for ds in zfs_datasets:
                # informational note if compression is effective
                if ds.get('compressratio') and ds['compressratio'] not in ('1.00x', '0.00x'):
                    results['recommendations'].append(
                        f"ZFS dataset {ds['name']} has compression ratio {ds['compressratio']}"
                    )
    if args.check_btrfs:
        btrfs_subvols = detect_btrfs_subvolumes()
        if btrfs_subvols:
            results['btrfs_subvolumes'] = btrfs_subvols
    if args.check_docker or args.check_podman or args.check_k8s:
        runtimes = ContainerRuntime.detect_runtimes()
        results['container_runtimes'] = runtimes
        if runtimes:
            results['container_stats'] = ContainerRuntime.get_all_container_stats(runtimes)
            if results['container_stats'].get('dangling_images'):
                results['recommendations'].append(
                    f"Clean {len(results['container_stats']['dangling_images'])} dangling images"
                )
    if args.check_hidden:
        hidden = detect_hidden_mountpoints()
        if hidden:
            results['hidden_mountpoints'] = hidden
            for h in hidden:
                results['issues'].append(
                    f"Hidden files under {h['mountpoint']}: {h['hidden_size_human']}"
                )
    if args.check_logs or args.check_journal:
        log_status = check_log_rotation()
        results['log_rotation'] = log_status
        if log_status['issues']:
            results['issues'].extend(log_status['issues'])
        if log_status['large_logs']:
            results['recommendations'].append(
                f"Rotate {len(log_status['large_logs'])} large log files"
            )
        if args.identify_processes and log_status['large_logs']:
            results['log_writers'] = identify_log_writers()
    if args.identify_processes:
        for fs in results['filesystems']:
            if fs.get('inode_percent', 0) > 50.0:
                inode_consumers = find_inode_consumers_by_process()
                if inode_consumers:
                    results['inode_consumers'] = inode_consumers
                    for comm, info in list(inode_consumers.items())[:3]:
                        results['recommendations'].append(
                            f"Process '{comm}' has {info['total_fds']} open files"
                        )
                break
    return results

def sanitize_label(label: str) -> str:
    """Sanitize label for perfdata."""
    if label == '/':
        return 'root'
    s = re.sub(r'[^A-Za-z0-9_.-]+', '_', label)
    s = s.strip('_') or 'root'
    return s

def _clamp_pct(x: float) -> float:
    try:
        return max(0.0, min(100.0, float(x)))
    except Exception:
        return 0.0

def main():
    """Main monitoring function."""
    args = parse_args()
    if args.self_test:
        return run_self_test()
    lock_fd = None
    if not args.no_lock:
        lock_fd = flock_nowait(args.lock_file)
        if not lock_fd:
            if args.high_freq:
                return EXIT_OK
            print("UNKNOWN - Could not acquire lock")
            return EXIT_UNK
    global _cache
    _cache = Cache(ttl=args.cache_ttl)
    mode = 'nagios'
    if args.zabbix:
        mode = 'zabbix'
    elif args.prom:
        mode = 'prom'
    elif args.raw:
        mode = 'raw'
    t0 = time.time()
    exclude_patterns = list(DEFAULT_EXCLUDES)
    if args.exclude:
        exclude_patterns.extend(args.exclude)
    if args.exclude_type:
        for t in args.exclude_type:
            if t not in SKIP_FS_TYPES:
                SKIP_FS_TYPES.append(t)
    if args.list:
        fs = get_filesystems_advanced(exclude_patterns, args.include_remote)
        for fsi in fs:
            print(f"{fsi['mountpoint']}\t{fsi['fstype']}\t{bytes_to_human(fsi['total'])}")
        return EXIT_OK
    if args.basic or (args.high_freq and not args.full_analysis):
        results = perform_basic_checks(exclude_patterns, args.include_remote)
    else:
        results = perform_full_analysis(args, exclude_patterns)
    if not results['filesystems']:
        if mode == 'nagios':
            print("UNKNOWN - No filesystems detected | exec_time=0ms")
        elif mode == 'raw':
            print(json.dumps({'s': EXIT_UNK, 'results': results, 'exec_ms': 0}))
        return EXIT_UNK
    overall_state = EXIT_OK
    critical_items: List[str] = []
    warning_items: List[str] = []
    rules = parse_thresholds(args.threshold, args.default_warn, args.default_crit)
    for fs in results['filesystems']:
        mp = fs['mountpoint']
        if 'error' in fs:
            if 'stale' in fs:
                warning_items.append(f"{mp}:stale")
                overall_state = max(overall_state, EXIT_WARN)
            continue
        used = fs['used']
        total = fs['total']
        use_pct = fs.get('use_percent', 0.0)
        inode_pct = fs.get('inode_percent', 0.0)
        rule = select_thresholds_for_mount(mp, rules)
        if evaluate_threshold(used, total, rule.crit_type, rule.crit_val):
            overall_state = EXIT_CRIT
            critical_items.append(f"{mp}:{use_pct:.1f}%")
        elif evaluate_threshold(used, total, rule.warn_type, rule.warn_val):
            overall_state = max(overall_state, EXIT_WARN)
            warning_items.append(f"{mp}:{use_pct:.1f}%")
        if inode_pct >= args.inode_crit:
            overall_state = EXIT_CRIT
            critical_items.append(f"{mp}:inodes:{inode_pct:.1f}%")
        elif inode_pct >= args.inode_warn:
            overall_state = max(overall_state, EXIT_WARN)
            warning_items.append(f"{mp}:inodes:{inode_pct:.1f}%")
    if 'issues' in results and results['issues']:
        overall_state = max(overall_state, EXIT_WARN)
    exec_ms = (time.time() - t0) * 1000.0
    state_text = ["OK", "WARNING", "CRITICAL", "UNKNOWN"][overall_state]
    if mode == 'raw':
        out = {
            's': overall_state,
            'results': results,
            'critical': critical_items[:10],
            'warning': warning_items[:10],
            'exec_ms': round(exec_ms, 2),
        }
        print(json.dumps(out, separators=(',', ':')))
        return overall_state
    msg_parts: List[str] = [state_text]
    if args.summary and results['filesystems']:
        valid_fs = [fs for fs in results['filesystems'] if 'error' not in fs]
        if valid_fs:
            top = sorted(valid_fs, key=lambda x: x.get('use_percent', 0.0), reverse=True)[:args.summary]
            tops = ", ".join(f"{fs['mountpoint']}={fs.get('use_percent', 0.0):.1f}%" for fs in top)
            msg_parts.append(f"Top:{tops}")
    valid_fs = [fs for fs in results['filesystems'] if 'error' not in fs]
    if valid_fs:
        inode_high = max(valid_fs, key=lambda x: x.get('inode_percent', 0.0), default=None)
        if inode_high and inode_high.get('inode_percent', 0.0) > 50:
            msg_parts.append(f"Inodes:{inode_high['mountpoint']}={inode_high['inode_percent']:.1f}%")
    if 'container_stats' in results and results['container_stats'].get('dangling_images'):
        count = len(results['container_stats']['dangling_images'])
        msg_parts.append(f"Dangling:{count}images")
    if 'log_rotation' in results and results['log_rotation'].get('journal'):
        journal = results['log_rotation']['journal']
        if journal['disk_usage'] > 1024**3:
            msg_parts.append(f"Journal:{journal['disk_usage_human']}")
    if args.high_freq:
        msg_parts.append(f"Time:{exec_ms:.1f}ms")
    perf: List[str] = []
    if args.smart_perf:
        fs_for_perf = []
        for fs in results['filesystems']:
            if 'error' in fs:
                continue
            mp = fs['mountpoint']
            rule = select_thresholds_for_mount(mp, rules)
            if evaluate_threshold(fs['used'], fs['total'], rule.warn_type, rule.warn_val) or \
               fs.get('inode_percent', 0) >= args.inode_warn:
                fs_for_perf.append(fs)
    else:
        valid_fs = [fs for fs in results['filesystems'] if 'error' not in fs]
        if args.perf_limit > 0:
            fs_for_perf = sorted(valid_fs, key=lambda x: x.get('use_percent', 0.0), reverse=True)[:args.perf_limit]
        else:
            fs_for_perf = valid_fs
    for fs in fs_for_perf:
        label = sanitize_label(fs['mountpoint'])
        rule = select_thresholds_for_mount(fs['mountpoint'], rules)
        if rule.warn_type == 'percent':
            warn_val = rule.warn_val
        else:
            warn_val = ((fs['total'] - rule.warn_val) / fs['total'] * 100) if fs['total'] > 0 else 0
        if rule.crit_type == 'percent':
            crit_val = rule.crit_val
        else:
            crit_val = ((fs['total'] - rule.crit_val) / fs['total'] * 100) if fs['total'] > 0 else 0
        warn_val = _clamp_pct(warn_val)
        crit_val = _clamp_pct(crit_val)
        perf.append(f"{label}_pct={fs.get('use_percent', 0.0)}%;{warn_val:.1f};{crit_val:.1f};0;100")
        if fs.get('inode_percent', 0.0) > 0:
            perf.append(f"{label}_inodes={fs.get('inode_percent', 0.0)}%;{args.inode_warn};{args.inode_crit};0;100")
    perf.append(f"exec_time={exec_ms:.2f}ms;;;0;1000")
    if 'container_stats' in results:
        stats = results['container_stats']
        if stats.get('total_images') is not None:
            perf.append(f"container_images={stats['total_images']};;;;")
        if stats.get('dangling_images'):
            perf.append(f"dangling_images={len(stats['dangling_images'])};;;;")
    if mode == 'nagios':
        print(f"{' - '.join(msg_parts)} | {' '.join(perf)}")
        if args.multiline and results['filesystems']:
            valid_fs = [fs for fs in results['filesystems'] if 'error' not in fs]
            for fs in sorted(valid_fs, key=lambda x: x.get('mountpoint', '')):
                line = f"{fs['mountpoint']} {fs.get('use_percent', 0.0):.1f}% used"
                if fs.get('inode_percent', 0.0) > 0:
                    line += f" (inodes {fs['inode_percent']:.1f}%)"
                if 'total' in fs and 'used' in fs and 'available' in fs:
                    line += f" [{bytes_to_human(fs['used'])}/{bytes_to_human(fs['total'])}, free {bytes_to_human(fs['available'])}]"
                print(line)
            if 'recommendations' in results and results['recommendations']:
                print("\nRecommendations:")
                for rec in results['recommendations'][:5]:
                    print(f"  • {rec}")
            if 'issues' in results and results['issues']:
                print("\nIssues:")
                for issue in results['issues'][:5]:
                    print(f"  ⚠ {issue}")
    elif mode == 'zabbix':
        output = {
            'status': state_text,
            'status_code': overall_state,
            'critical': critical_items,
            'warning': warning_items,
            'metrics': results,
            'exec_ms': round(exec_ms, 2)
        }
        print(json.dumps(output))
    elif mode == 'prom':
        for fs in results['filesystems']:
            if 'error' in fs:
                continue
            mp = fs['mountpoint']
            labels = f'mount="{prom_escape(mp)}",device="{prom_escape(fs["device"])}",fstype="{fs["fstype"]}"'
            print(f'disk_usage_percent{{{labels}}} {fs.get("use_percent", 0.0)}')
            print(f'disk_total_bytes{{{labels}}} {fs["total"]}')
            print(f'disk_used_bytes{{{labels}}} {fs["used"]}')
            print(f'disk_available_bytes{{{labels}}} {fs["available"]}')
            if fs.get('inode_percent', 0.0) > 0:
                print(f'disk_inode_usage_percent{{{labels}}} {fs.get("inode_percent", 0.0)}')
        if 'container_stats' in results:
            stats = results['container_stats']
            if stats.get('total_images'):
                print(f'container_images_total {stats["total_images"]}')
            if stats.get('dangling_images'):
                print(f'container_dangling_images {len(stats["dangling_images"])}')
        if 'log_rotation' in results and results['log_rotation'].get('journal'):
            journal = results['log_rotation']['journal']
            if journal['available']:
                print(f'systemd_journal_bytes {journal["disk_usage"]}')
        print(f'disk_check_duration_ms {exec_ms:.2f}')
    # best effort: close lock
    if lock_fd:
        try:
            os.close(lock_fd)
        except Exception:
            pass
    return overall_state

# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(EXIT_UNK)
    except Exception as e:
        if '--debug' in sys.argv:
            import traceback
            traceback.print_exc()
        print(f"UNKNOWN - Unexpected error: {e}")
        sys.exit(EXIT_UNK)
