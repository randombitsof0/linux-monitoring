#!/usr/bin/env python3
"""
mem_health_check.py — Linux memory health check

Purpose:
--------
This script provides a comprehensive memory health monitoring for Linux systems by
analyzing multiple metrics beyond simple memory usage.

Key Features:
-------------
* PSI (Pressure Stall Information) aware - detects actual memory pressure
* Swap activity monitoring - tracks active swapping, not just swap usage
* NUMA awareness - monitors per-node memory on multi-socket systems
* Historical trending - provides capacity planning recommendations
* Multiple output formats - Nagios, Prometheus, Zabbix, checkmk
* High-performance - can run every second with minimal overhead

Supported Platforms:
--------------------
Any Linux with kernel 4.20+ (for full PSI support)

Version: 1.0.0
License: MIT
"""

import argparse
import errno
import fcntl
import json
import mmap
import os
import re
import signal
import sys
import time
from collections import deque
from typing import Dict, Any, Tuple, List, Optional

# Exit codes following Nagios plugin standards
# These are used by monitoring systems to determine alert severity
EXIT_OK, EXIT_WARN, EXIT_CRIT, EXIT_UNK = 0, 1, 2, 3

# Default file paths
# Using /dev/shm (tmpfs) for state/lock files provides better performance
# as these are memory-backed and avoid disk I/O
STATE_DEFAULT = "/dev/shm/mem_health_check.state"  # Stores previous metrics for rate calculations
LOCK_DEFAULT  = "/dev/shm/mem_health_check.lock"   # Prevents concurrent executions
HIST_DEFAULT  = "/var/tmp/mem_health_check.history.jsonl"  # Long-term history for trending

# Version information
__version__ = "1.0.0"

# ============================================================================
# PERFORMANCE OPTIMIZATIONS
# ============================================================================

# Pre-compiled regular expressions for faster parsing
# These patterns extract key-value pairs from /proc files
# Using compiled regex is ~3x faster than string splitting for large files

# Pattern for /proc/meminfo: "MemTotal:    32765636 kB"
RE_MEMINFO = re.compile(rb'^(\w+):\s+(\d+)', re.MULTILINE)

# Pattern for /proc/vmstat: "pgfault 12345"
RE_VMSTAT = re.compile(rb'^(\w+)\s+(\d+)$', re.MULTILINE)

# Pattern for PSI data: "some avg10=0.00 avg60=0.00 avg300=0.00 total=12345"
RE_PSI_SOME = re.compile(rb'some.*?avg10=(\d+\.?\d*).*?avg60=(\d+\.?\d*).*?avg300=(\d+\.?\d*)')

# ============================================================================
# CACHING SYSTEM
# ============================================================================

class Cache:
    """
    Simple TTL-based cache for expensive operations.

    Used to cache:
    - NUMA node discovery (topology rarely changes)
    - cgroup paths (container config is static)
    - Other slow operations that don't change frequently
    """
    def __init__(self, ttl: int = 60):
        """
        Initialize cache with TTL (time-to-live) in seconds.

        Args:
            ttl: Seconds before cached entries expire
        """
        self.ttl = ttl
        self.data = {}
        self.timestamps = {}

    def get(self, key: str, generator, *args):
        """
        Get cached value or generate and cache it.

        Args:
            key: Cache key
            generator: Function to call if cache miss
            *args: Arguments to pass to generator

        Returns:
            Cached or newly generated value
        """
        now = time.time()

        # Check if we have a valid cached entry
        if key in self.data and now - self.timestamps[key] < self.ttl:
            return self.data[key]

        # Cache miss or expired - generate new value
        value = generator(*args)
        self.data[key] = value
        self.timestamps[key] = now
        return value

# Global cache instance
_cache = Cache(ttl=60)  # 1-minute default TTL

# ============================================================================
# SIGNAL HANDLING
# ============================================================================

class GracefulExit:
    """
    Handle SIGTERM/SIGINT for clean shutdown.
    Important for containerized environments where SIGTERM is common.
    """
    def __init__(self):
        self.exit_now = False
        signal.signal(signal.SIGTERM, self.handle_signal)
        signal.signal(signal.SIGINT, self.handle_signal)

    def handle_signal(self, signum, frame):
        """Set flag to exit gracefully on next check."""
        self.exit_now = True

# ============================================================================
# FAST FILE I/O FUNCTIONS
# ============================================================================

def _is_virtual_fs(path: str) -> bool:
    """
    Heuristic: detect virtual filesystems that often don't support mmap and/or
    report st_size=0 even when they have content (e.g., /proc, /sys, /dev).
    """
    return path.startswith('/proc/') or path.startswith('/sys/') or path.startswith('/dev/')

def read_file_mmap(path: str) -> bytes:
    """
    Read file using memory-mapped I/O for better performance.

    Memory mapping is faster for large files as it:
    - Avoids copying data from kernel to user space
    - Allows the kernel to manage caching efficiently
    - Reduces memory allocations

    FIXED/OPTIMIZED:
    ----------------
    • Do NOT rely on st_size to detect emptiness: many procfs files report 0.
    • Skip mmap on virtual filesystems (/proc, /sys, /dev) because many do not
      support mmap at all and will raise EINVAL. Fall back to a plain read.
    """
    try:
        # Fast path for virtual filesystems: plain read
        if _is_virtual_fs(path):
            with open(path, 'rb') as f:
                return f.read()

        # Regular files: try mmap first, then graceful fallback
        with open(path, 'rb') as f:
            try:
                # Map the entire file (length 0 means "whole file")
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                    # Read entire mapped region
                    return m.read()
            except (OSError, ValueError):
                # Some files don't support mmap -> fallback
                return f.read()
    except OSError:
        # Propagate empty bytes; callers handle missing/invalid data
        return b''

def parse_meminfo_fast() -> Dict[str, int]:
    """
    Parse /proc/meminfo using optimized regex matching.

    /proc/meminfo contains memory statistics in format:
    MemTotal:       32765636 kB
    MemFree:         1234567 kB
    MemAvailable:   12345678 kB

    Returns:
        Dictionary mapping metric names to values in kB
    """
    data = read_file_mmap('/proc/meminfo')
    # Use compiled regex to extract all key-value pairs at once
    # This is much faster than line-by-line parsing
    return {m[0].decode(): int(m[1]) for m in RE_MEMINFO.findall(data)}

def parse_vmstat_fast() -> Dict[str, int]:
    """
    Parse /proc/vmstat for VM statistics.

    /proc/vmstat contains counters like:
    pgfault 12345      (minor page faults)
    pgmajfault 123     (major page faults requiring disk I/O)
    pswpin 456         (pages swapped in from disk)
    pswpout 789        (pages swapped out to disk)

    Returns:
        Dictionary mapping counter names to values
    """
    data = read_file_mmap('/proc/vmstat')
    return {m[0].decode(): int(m[1]) for m in RE_VMSTAT.findall(data)}

def read_psi_fast() -> Tuple[bool, Optional[float], Optional[float], Optional[float]]:
    """
    Read PSI (Pressure Stall Information) metrics.

    PSI shows the percentage of time tasks were stalled waiting for memory.
    Available in kernel 4.20+ (RHEL 8+, Ubuntu 20.04+)

    Format in /proc/pressure/memory:
    some avg10=0.00 avg60=0.00 avg300=0.00 total=12345
    full avg10=0.00 avg60=0.00 avg300=0.00 total=12345

    Returns:
        Tuple of (psi_available, avg10%, avg60%, avg300%)
        Returns (False, None, None, None) if PSI not available
    """
    path = '/proc/pressure/memory'
    if not os.path.exists(path):
        # PSI not available (older kernel or disabled)
        return False, None, None, None

    try:
        data = read_file_mmap(path)
        # Extract "some" line (at least one task stalled)
        # "full" line means all tasks stalled (more severe)
        match = RE_PSI_SOME.search(data)
        if match:
            return True, float(match[1]), float(match[2]), float(match[3])
    except Exception:
        pass
    return False, None, None, None

def flock_nowait(path: str) -> Optional[int]:
    """
    Acquire non-blocking exclusive lock.

    Prevents multiple instances from running simultaneously,
    which could corrupt state files or cause incorrect rate calculations.

    Args:
        path: Lock file path

    Returns:
        File descriptor if lock acquired, None if already locked
    """
    try:
        # Create lock file if doesn't exist (O_CREAT)
        # Open for read/write (O_RDWR)
        # Set permissions to 0600 (user read/write only)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)

        # Try to acquire exclusive lock (LOCK_EX)
        # Non-blocking (LOCK_NB) - fail immediately if locked
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except OSError:
        # Lock already held by another process
        return None

# ============================================================================
# STATE MANAGEMENT
# ============================================================================

class StateManager:
    """
    Manages persistent state between script executions.

    State is used to:
    - Calculate rates (swap/sec, faults/sec) by comparing with previous values
    - Track cgroup OOM events
    - Store timestamps for accurate rate calculations

    Uses caching to avoid repeated reads in high-frequency mode.
    """

    def __init__(self, path: str):
        """
        Initialize state manager.

        Args:
            path: Path to state file (JSON format)
        """
        self.path = path
        self._cache = None
        self._cache_time = 0
        self._cache_ttl = 0.5  # Cache for 500ms in high-freq mode

    def read(self) -> Dict[str, Any]:
        """
        Read state from disk with caching.

        Returns:
            Previous state dictionary or empty dict if not found
        """
        now = time.time()

        # Return cached value if still valid
        if self._cache and now - self._cache_time < self._cache_ttl:
            return self._cache

        try:
            # Read and parse JSON state
            with open(self.path, 'rb') as f:
                self._cache = json.loads(f.read())
                self._cache_time = now
                return self._cache
        except (FileNotFoundError, json.JSONDecodeError):
            # No previous state or corrupted
            return {}

    def write(self, data: Dict[str, Any]):
        """
        Write state to disk atomically.

        Atomic write prevents corruption if script is interrupted.

        Args:
            data: State dictionary to persist
        """
        tmp = self.path + '.tmp'

        # Serialize to compact JSON
        content = json.dumps(data, separators=(',', ':')).encode()

        # Write to temp file in single syscall
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, content)
            os.fsync(fd)  # Ensure written to storage
        finally:
            os.close(fd)

        # Atomic rename - old state replaced instantly
        os.replace(tmp, self.path)

        # Update cache
        self._cache = data
        self._cache_time = time.time()

# ============================================================================
# HISTORY MANAGEMENT (FOR TRENDING)
# ============================================================================

class AsyncHistoryWriter:
    """
    Manages historical metrics for long-term trending.

    History is used to:
    - Detect if system is consistently under/over-provisioned
    - Provide capacity planning recommendations
    - Track memory pressure patterns over time

    Uses bucketing to limit storage (e.g., one entry per hour/day).
    Writes are deferred to avoid blocking the main check.
    """

    def __init__(self, path: str, interval_hours: int = 24):
        """
        Initialize history writer.

        Args:
            path: Path to history file (JSONL format - one JSON object per line)
            interval_hours: Hours per bucket (24 = daily buckets)
        """
        self.path = path
        self.interval_secs = interval_hours * 3600
        self.pending = deque(maxlen=1)  # Only keep latest update
        self.last_write = 0
        self.write_interval = 10  # Batch writes every 10 seconds

    def should_update(self, now: float) -> bool:
        """Check if enough time passed to write history."""
        return now - self.last_write >= self.write_interval

    def queue_update(self, metrics: Dict[str, Any], now: float):
        """
        Queue metrics for eventual write.

        Args:
            metrics: Current metrics to record
            now: Current timestamp
        """
        # Calculate which time bucket this belongs to
        bucket_start = int(now // self.interval_secs) * self.interval_secs
        self.pending.append((bucket_start, metrics, now))

    def flush(self, window_days: int = 365):
        """
        Write pending updates to disk.

        Updates existing bucket or creates new one.
        Maintains rolling window of historical data.

        Args:
            window_days: Days of history to retain
        """
        if not self.pending:
            return

        bucket_start, metrics, now = self.pending[-1]

        # Format bucket label (e.g., "2024-01-15T00:00")
        bucket_label = time.strftime("%Y-%m-%dT%H:00", time.localtime(bucket_start))

        # Calculate cutoff for old data
        cutoff = now - window_days * 86400

        # Read existing history
        rows = []
        try:
            if os.path.exists(self.path):
                with open(self.path, 'rb') as f:
                    for line in f:
                        try:
                            r = json.loads(line)
                            # Keep if within window or has bucket label
                            if r.get('ts', 0) >= cutoff or r.get('bucket'):
                                rows.append(r)
                        except:
                            continue  # Skip corrupted lines
        except:
            pass

        # Find or create bucket for this time period
        row = None
        for r in rows:
            if r.get('bucket') == bucket_label:
                row = r
                break

        if not row:
            # Create new bucket with initial values
            row = {
                'bucket': bucket_label,
                'ts': int(now),
                'min_memavail_pct': 100.0,    # Track minimum available
                'avg_memavail_pct': 0.0,       # Track average
                'samples': 0,                   # Sample count for average
                'max_psi10': 0.0,              # Track maximum pressure
                'max_psi300': 0.0,             # Track sustained pressure
                'max_swapin_s': 0.0,           # Track maximum swap activity
            }
            rows.append(row)

        # Update bucket statistics
        # These aggregations help identify patterns over time
        mv = float(metrics.get('mem_avail_pct', 0.0))
        row['min_memavail_pct'] = min(row['min_memavail_pct'], mv)

        # Calculate running average
        n = row['samples']
        row['avg_memavail_pct'] = (row['avg_memavail_pct'] * n + mv) / (n + 1)
        row['samples'] = n + 1

        # Track maximums for pressure indicators
        row['max_psi10'] = max(row['max_psi10'], float(metrics.get('psi10_pct') or 0.0))
        row['max_psi300'] = max(row['max_psi300'], float(metrics.get('psi300_pct') or 0.0))
        row['max_swapin_s'] = max(row['max_swapin_s'], float(metrics.get('pswpin_per_s', 0.0)))

        # Write updated history atomically
        tmp = self.path + '.tmp'
        with open(tmp, 'wb') as f:
            for r in rows:
                f.write(json.dumps(r, separators=(',', ':')).encode())
                f.write(b'\n')
        os.replace(tmp, self.path)

        self.pending.clear()
        self.last_write = now

# ============================================================================
# ANALYSIS FUNCTIONS
# ============================================================================

def find_swap_offender_fast(threshold_kb: int = 1024) -> Tuple[Optional[str], int]:
    """
    Find process using the most swap space.

    Only reports processes using more than threshold_kb to avoid noise.
    Useful for identifying memory leaks or misbehaving applications.

    Args:
        threshold_kb: Minimum swap usage to report (default 1MB)

    Returns:
        Tuple of (command_line, swap_kb) or (None, 0) if none found
    """
    max_sw = 0
    max_pid = None
    cmd = None

    try:
        # Scan /proc for process directories
        # os.scandir is faster than os.listdir for getting file attributes
        with os.scandir('/proc') as entries:
            for entry in entries:
                # Skip non-process directories
                if not entry.name.isdigit():
                    continue

                # Check swap usage in /proc/PID/status
                # This file is smaller than smaps_rollup and faster to parse
                try:
                    status_path = f'/proc/{entry.name}/status'
                    with open(status_path, 'rb') as f:
                        for line in f:
                            if line.startswith(b'VmSwap:'):
                                # Extract swap size in kB
                                sw = int(line.split()[1])
                                if sw > max_sw and sw > threshold_kb:
                                    max_sw = sw
                                    max_pid = int(entry.name)
                                break  # Found VmSwap, no need to read rest
                except:
                    # Process might have exited, permission denied, etc.
                    continue

        if max_pid and max_sw > threshold_kb:
            # Get command line of the biggest swap user
            try:
                with open(f'/proc/{max_pid}/cmdline', 'rb') as f:
                    # Limit read to avoid huge command lines
                    data = f.read(256)
                    # Command line args are separated by null bytes
                    parts = data.split(b'\0')
                    cmd = b' '.join(p for p in parts if p).decode(errors='replace').strip()
            except:
                cmd = f"PID {max_pid}"  # Process might have exited

        return cmd or None, max_sw
    except Exception:
        return None, 0

# ============================================================================
# NUMA SUPPORT
# ============================================================================

def get_numa_nodes_cached() -> List[str]:
    """
    Get list of NUMA nodes with caching.

    NUMA (Non-Uniform Memory Access) systems have multiple memory nodes.
    Performance degrades if a CPU accesses memory from a remote node.

    Returns:
        List of paths to NUMA node directories
    """
    def discover():
        """Discover NUMA nodes from sysfs."""
        base = '/sys/devices/system/node'
        if not os.path.isdir(base):
            return []  # Not a NUMA system

        # Find all nodeN directories
        return [os.path.join(base, n) for n in os.listdir(base)
                if n.startswith('node')]

    # Cache discovery as NUMA topology doesn't change at runtime
    return _cache.get('numa_nodes', discover)

def numa_check_fast(warn: float, crit: float) -> Tuple[Optional[str], Optional[float], int]:
    """
    Check NUMA node memory availability.

    Important for databases and HPC applications where NUMA imbalance
    can cause severe performance degradation.

    Args:
        warn: Warning threshold for node availability %
        crit: Critical threshold for node availability %

    Returns:
        Tuple of (worst_node_name, worst_availability%, exit_code)
    """
    nodes = get_numa_nodes_cached()
    if not nodes:
        return None, None, EXIT_OK

    min_node = None
    min_pct = 100.0

    for node_path in nodes:
        try:
            # Read node-specific meminfo
            # Format similar to /proc/meminfo but per-node
            with open(os.path.join(node_path, 'meminfo'), 'rb') as f:
                data = f.read()

            # Parse just the fields we need
            total = free = file = 0
            for line in data.split(b'\n'):
                if line.startswith(b'Node'):
                    parts = line.split()
                    if len(parts) >= 4:
                        key = parts[2]
                        val = int(parts[3])
                        if key == b'MemTotal:':
                            total = val
                        elif key == b'MemFree:':
                            free = val
                        elif key == b'FilePages:':
                            file = val  # File cache can be reclaimed

            if total:
                # Calculate available memory percentage
                # Including file cache as it can be reclaimed if needed
                pct = ((free + file) * 100.0 / total)

                if pct < min_pct:
                    min_pct = pct
                    min_node = os.path.basename(node_path)

                # Early exit if critical threshold breached
                # No need to check other nodes
                if pct <= crit:
                    return min_node, pct, EXIT_CRIT
        except:
            continue

    # Determine exit code based on worst node
    if min_pct <= warn:
        return min_node, min_pct, EXIT_WARN

    return min_node, min_pct, EXIT_OK

# ============================================================================
# ADDITIONAL CHECKS
# ============================================================================

def check_memory_fragmentation() -> float:
    """
    Check memory fragmentation level.

    Fragmentation occurs when free memory is split into small chunks.
    This can prevent allocation of large contiguous memory blocks,
    important for huge pages, DMA buffers, and some database operations.

    Returns:
        Fragmentation score 0-100 (0=no fragmentation, 100=severe)
    """
    try:
        # /proc/buddyinfo shows free pages by order (power of 2)
        # Order 0 = 4KB, Order 1 = 8KB, Order 2 = 16KB, etc.
        with open('/proc/buddyinfo', 'rb') as f:
            lines = f.readlines()

        for line in lines:
            # Focus on Normal zone (main memory)
            if b'Normal' in line:
                parts = line.split()
                if len(parts) >= 6:
                    # Extract free page counts by order
                    orders = [int(x) for x in parts[4:]]
                    if len(orders) >= 5:
                        # Simple heuristic: compare low vs high order pages
                        # Many small fragments = high fragmentation
                        low_order = sum(orders[:2])   # 4KB-8KB chunks
                        high_order = sum(orders[3:])  # 32KB+ chunks

                        if low_order > 0:
                            # High ratio of small chunks = fragmented
                            fragmentation = min(100, (1 - high_order/low_order) * 100)
                            return fragmentation
        return 0.0
    except:
        return 0.0

def detect_container_limits() -> Dict[str, Any]:
    """
    Auto-detect if running in a container and get memory limits.

    Containers may have memory limits that differ from host memory.
    Important for accurate threshold calculations.

    Returns:
        Dictionary with 'container' boolean and 'limit_bytes' if found
    """
    # Check common cgroup paths for memory limits
    cgroup_paths = [
        '/sys/fs/cgroup/memory/memory.limit_in_bytes',  # cgroup v1
        '/sys/fs/cgroup/memory.max',                    # cgroup v2
    ]

    for path in cgroup_paths:
        try:
            with open(path, 'r') as f:
                limit = f.read().strip()
                # Check if limit is set (not 'max' or huge number)
                if limit != 'max' and int(limit) < (1 << 62):  # Less than "unlimited"
                    return {'container': True, 'limit_bytes': int(limit)}
        except:
            continue

    return {'container': False}

def generate_advice(hist_rows: List[Dict[str, Any]], min_buckets: int = 30) -> Optional[str]:
    """
    Generate provisioning advice based on historical data.

    Analyzes patterns over time to determine if system is:
    - Under-provisioned (needs more RAM)
    - Over-provisioned (has excess RAM)
    - Properly sized

    Args:
        hist_rows: Historical metric buckets
        min_buckets: Minimum history needed for reliable advice

    Returns:
        Provisioning recommendation or None if insufficient data
    """
    if len(hist_rows) < min_buckets:
        return None  # Not enough history for reliable advice

    # Extract metrics from history
    min_avails = [r.get('min_memavail_pct', 0.0) for r in hist_rows]
    max_psi10s = [r.get('max_psi10', 0.0) for r in hist_rows]
    max_psi300s = [r.get('max_psi300', 0.0) for r in hist_rows]
    max_swapins = [r.get('max_swapin_s', 0.0) for r in hist_rows]

    # Calculate percentiles for analysis
    def percentile(values: List[float], p: float) -> float:
        """Calculate percentile of values."""
        if not values:
            return 0.0
        values = sorted(values)
        idx = max(0, min(len(values) - 1, int(round((p / 100.0) * (len(values) - 1)))))
        return values[idx]

    min_avails = [r.get('min_memavail_pct', 0.0) for r in hist_rows]
    max_psi10s = [r.get('max_psi10', 0.0) for r in hist_rows]
    max_psi300s = [r.get('max_psi300', 0.0) for r in hist_rows]
    max_swapins = [r.get('max_swapin_s', 0.0) for r in hist_rows]

    p5_mem = percentile(min_avails, 5)
    p50_mem = percentile(min_avails, 50)
    p95_psi10 = percentile(max_psi10s, 95)
    p95_psi300 = percentile(max_psi300s, 95)
    p95_swapin = percentile(max_swapins, 95)

    # Under-provisioned: High pressure + swap activity
    if (p95_psi10 >= 20.0 or p95_psi300 >= 5.0) and (p95_swapin >= 50.0 or p5_mem <= 5.0):
        return "Under-provisioned: Sustained pressure + swap activity detected. Consider adding RAM."

    # Over-provisioned: Consistently low utilization
    if p95_psi10 < 1.0 and p95_swapin < 1.0 and p5_mem > 40.0 and p50_mem > 50.0:
        return "Over-provisioned: Consistently low pressure and high free memory. Could reduce RAM."

    # Well-provisioned
    if p95_psi10 < 10.0 and p95_swapin < 10.0 and p5_mem > 10.0:
        return "Well-provisioned: Memory pressure within acceptable limits."

    return None

# ============================================================================
# COMMAND-LINE PARSING
# ============================================================================

def parse_args():
    """
    Parse command-line arguments.

    Provides extensive options for customization, thresholds, and output formats.
    """
    ap = argparse.ArgumentParser(
        description="High-performance memory health check for Linux systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic check with Nagios output
  %(prog)s

  # High-frequency monitoring (1Hz)
  %(prog)s --high-freq --no-lock --raw

  # Database server with NUMA
  %(prog)s --check-numa --numa-warn 10 --check-fragmentation

  # Container with Prometheus output
  %(prog)s --prom --no-history

  # Generate provisioning advice
  %(prog)s --advise --advise-min-buckets 30
        """
    )

    # Output format options
    output_group = ap.add_argument_group('Output Formats')
    output_group.add_argument("--nagios", action="store_true",
                             help="Nagios/Icinga format with perfdata (default)")
    output_group.add_argument("--zabbix", action="store_true",
                             help="JSON format for Zabbix")
    output_group.add_argument("--prom", action="store_true",
                             help="Prometheus text exposition format")
    output_group.add_argument("--checkmk", action="store_true",
                             help="Check_MK local check format")
    output_group.add_argument("--raw", action="store_true",
                             help="Minimal JSON for high-frequency collection")

    # Performance options
    perf_group = ap.add_argument_group('Performance')
    perf_group.add_argument("--high-freq", action="store_true",
                           help="Optimize for >1Hz execution (skip some features)")
    perf_group.add_argument("--no-history", action="store_true",
                           help="Disable history writing (reduces I/O)")
    perf_group.add_argument("--no-lock", action="store_true",
                           help="Skip locking (assumes single instance)")
    perf_group.add_argument("--cache-ttl", type=int, default=60,
                           help="Cache TTL for slow operations in seconds (default: 60)")

    # Memory thresholds
    thresh_group = ap.add_argument_group('Memory Thresholds')
    thresh_group.add_argument("-m", "--mem-warn", type=float, default=10.0,
                             help="Warning when MemAvailable%% <= this (default: 10)")
    thresh_group.add_argument("-M", "--mem-crit", type=float, default=2.0,
                             help="Critical when MemAvailable%% <= this (default: 2)")

    # PSI (Pressure) thresholds
    psi_group = ap.add_argument_group('PSI Thresholds')
    psi_group.add_argument("--psi10-warn", type=float, default=10.0,
                          help="Warning when PSI avg10 >= this (default: 10)")
    psi_group.add_argument("--psi10-crit", type=float, default=20.0,
                          help="Critical when PSI avg10 >= this (default: 20)")
    psi_group.add_argument("--psi300-warn", type=float, default=1.0,
                          help="Warning when PSI avg300 >= this (default: 1)")
    psi_group.add_argument("--psi300-crit", type=float, default=5.0,
                          help="Critical when PSI avg300 >= this (default: 5)")

    # Swap thresholds
    swap_group = ap.add_argument_group('Swap Thresholds')
    swap_group.add_argument("--swapin-warn", type=float, default=10.0,
                           help="Warning when swap-in rate >= this pages/sec (default: 10)")
    swap_group.add_argument("--swapin-crit", type=float, default=50.0,
                           help="Critical when swap-in rate >= this pages/sec (default: 50)")

    # Additional checks
    feature_group = ap.add_argument_group('Additional Features')
    feature_group.add_argument("--find-offender", action="store_true",
                              help="Identify process using most swap (on warn/crit)")
    feature_group.add_argument("--offender-threshold", type=int, default=10240,
                              help="Min swap KB to report offender (default: 10MB)")
    feature_group.add_argument("--check-numa", action="store_true",
                              help="Check NUMA node memory balance")
    feature_group.add_argument("--numa-warn", type=float, default=5.0,
                              help="NUMA warning threshold %% (default: 5)")
    feature_group.add_argument("--numa-crit", type=float, default=2.0,
                              help="NUMA critical threshold %% (default: 2)")
    feature_group.add_argument("--check-fragmentation", action="store_true",
                              help="Check memory fragmentation level")

    # File paths
    path_group = ap.add_argument_group('File Paths')
    path_group.add_argument("--state-file", default=STATE_DEFAULT,
                           help=f"State file path (default: {STATE_DEFAULT})")
    path_group.add_argument("--lock-file", default=LOCK_DEFAULT,
                           help=f"Lock file path (default: {LOCK_DEFAULT})")
    path_group.add_argument("--history-file", default=HIST_DEFAULT,
                           help=f"History file path (default: {HIST_DEFAULT})")

    # Historical analysis
    history_group = ap.add_argument_group('Historical Analysis')
    history_group.add_argument("--advise", action="store_true",
                              help="Generate provisioning advice from history")
    history_group.add_argument("--advise-window-days", type=int, default=365,
                              help="Days of history to analyze (default: 365)")
    history_group.add_argument("--advise-min-buckets", type=int, default=30,
                              help="Min history buckets for advice (default: 30)")
    history_group.add_argument("--advise-interval-hours", type=int, default=24,
                              help="Hours per history bucket (default: 24)")

    # Utility options
    util_group = ap.add_argument_group('Utility')
    util_group.add_argument("--self-test", action="store_true",
                           help="Run self-test and exit")
    util_group.add_argument("--version", action="version",
                           version=f"%(prog)s {__version__}")
    util_group.add_argument("--debug", action="store_true",
                           help="Enable debug output")

    return ap.parse_args()

# ============================================================================
# SELF-TEST FUNCTIONALITY
# ============================================================================

def run_self_test(args) -> int:
    """
    Run comprehensive self-test of all components.

    Tests:
    - /proc file access
    - PSI availability
    - State file operations
    - Lock mechanism
    - NUMA detection
    - Container detection

    Returns:
        EXIT_OK if all tests pass, EXIT_UNK otherwise
    """
    print("Memory Health Check Self-Test")
    print("=" * 40)

    tests = []

    # Test 1: Check /proc/meminfo access
    print("Testing /proc/meminfo access...", end=" ")
    try:
        mi = parse_meminfo_fast()
        if 'MemTotal' in mi and mi['MemTotal'] > 0:
            tests.append(("meminfo", "OK"))
            print("OK")
        else:
            tests.append(("meminfo", "FAIL: Invalid data"))
            print("FAIL")
    except Exception as e:
        tests.append(("meminfo", f"FAIL: {e}"))
        print(f"FAIL: {e}")

    # Test 2: Check /proc/vmstat access
    print("Testing /proc/vmstat access...", end=" ")
    try:
        vm = parse_vmstat_fast()
        if 'pgfault' in vm:
            tests.append(("vmstat", "OK"))
            print("OK")
        else:
            tests.append(("vmstat", "FAIL: Missing expected counters"))
            print("FAIL")
    except Exception as e:
        tests.append(("vmstat", f"FAIL: {e}"))
        print(f"FAIL: {e}")

    # Test 3: Check PSI availability
    print("Testing PSI (Pressure Stall Info)...", end=" ")
    psi_ok, psi10, _, _ = read_psi_fast()
    if psi_ok:
        tests.append(("PSI", f"OK (current: {psi10:.2f}%)"))
        print(f"OK (avg10={psi10:.2f}%)")
    else:
        tests.append(("PSI", "Not available (kernel <4.20 or disabled)"))
        print("Not available (kernel <4.20 or disabled)")

    # Test 4: State file operations
    print("Testing state file operations...", end=" ")
    try:
        test_state = args.state_file + '.test'
        state_mgr = StateManager(test_state)
        test_data = {'test': True, 'ts': int(time.time())}
        state_mgr.write(test_data)
        read_data = state_mgr.read()
        if read_data.get('test') == True:
            tests.append(("state", "OK"))
            print("OK")
            os.unlink(test_state)
        else:
            tests.append(("state", "FAIL: Read/write mismatch"))
            print("FAIL")
    except Exception as e:
        tests.append(("state", f"FAIL: {e}"))
        print(f"FAIL: {e}")

    # Test 5: Lock mechanism
    print("Testing lock mechanism...", end=" ")
    try:
        test_lock = args.lock_file + '.test'
        fd1 = flock_nowait(test_lock)
        if fd1:
            # Try to acquire again (should fail)
            fd2 = flock_nowait(test_lock)
            if fd2:
                tests.append(("lock", "FAIL: Double lock acquired"))
                print("FAIL: Double lock")
                os.close(fd2)
            else:
                tests.append(("lock", "OK"))
                print("OK")
            os.close(fd1)
            os.unlink(test_lock)
        else:
            tests.append(("lock", "FAIL: Could not acquire initial lock"))
            print("FAIL")
    except Exception as e:
        tests.append(("lock", f"FAIL: {e}"))
        print(f"FAIL: {e}")

    # Test 6: NUMA detection
    print("Testing NUMA detection...", end=" ")
    numa_nodes = get_numa_nodes_cached()
    if numa_nodes:
        tests.append(("NUMA", f"OK ({len(numa_nodes)} nodes)"))
        print(f"OK ({len(numa_nodes)} nodes)")
    else:
        tests.append(("NUMA", "Not available or single node"))
        print("Not NUMA system")

    # Test 7: Container detection
    print("Testing container detection...", end=" ")
    container_info = detect_container_limits()
    if container_info['container']:
        limit_mb = container_info['limit_bytes'] // (1024 * 1024)
        tests.append(("container", f"Yes (limit: {limit_mb}MB)"))
        print(f"Yes (limit: {limit_mb}MB)")
    else:
        tests.append(("container", "No (or no limits)"))
        print("No")

    # Test 8: Performance measurement
    print("Testing performance...", end=" ")
    try:
        # Measure average ms/check across multiple iterations for stability
        iters = 10
        t0 = time.time()
        for _ in range(iters):
            parse_meminfo_fast()
            parse_vmstat_fast()
            read_psi_fast()
        elapsed_ms_per_check = (time.time() - t0) * 1000.0 / iters
        tests.append(("performance", f"{elapsed_ms_per_check:.2f}ms per check"))
        print(f"{elapsed_ms_per_check:.2f}ms per check")
    except Exception as e:
        tests.append(("performance", f"FAIL: {e}"))
        print(f"FAIL: {e}")

    # Summary
    print("\n" + "=" * 40)
    print("Test Summary:")
    all_ok = True
    for name, status in tests:
        print(f"  {name:15s}: {status}")
        if "FAIL" in status:
            all_ok = False

    print("=" * 40)
    if all_ok:
        print("✓ All tests passed!")
        return EXIT_OK
    else:
        print("✗ Some tests failed")
        return EXIT_UNK

# ============================================================================
# MAIN MONITORING FUNCTION
# ============================================================================

def main():
    """
    Main monitoring function.

    Workflow:
    1. Parse arguments and validate
    2. Acquire lock (if enabled)
    3. Collect current metrics
    4. Compare with previous state for rates
    5. Evaluate thresholds
    6. Generate output in requested format
    """
    # Set secure file permissions
    os.umask(0o077)

    # Parse command-line arguments
    args = parse_args()

    # Enable debug if requested
    if args.debug:
        import logging
        logging.basicConfig(level=logging.DEBUG,
                          format='%(asctime)s - %(levelname)s - %(message)s')
        logging.debug("Debug mode enabled")

    # Run self-test if requested
    if args.self_test:
        return run_self_test(args)

    # Configure global cache TTL
    global _cache
    _cache = Cache(ttl=args.cache_ttl)

    # Set up graceful shutdown handler
    graceful = GracefulExit()

    # Determine output format
    # Default to Nagios format if none specified
    mode = "nagios"
    if args.zabbix:
        mode = "zabbix"
    elif args.prom:
        mode = "prom"
    elif args.checkmk:
        mode = "checkmk"
    elif args.raw:
        mode = "raw"

    # ========================================================================
    # VALIDATION
    # ========================================================================

    # Validate threshold relationships
    # Warning thresholds should trigger before critical
    if not (args.mem_warn > args.mem_crit):
        print("UNKNOWN - mem_warn must be > mem_crit")
        return EXIT_UNK

    if not (args.psi10_warn < args.psi10_crit):
        print("UNKNOWN - psi10_warn must be < psi10_crit")
        return EXIT_UNK

    if not (args.psi300_warn < args.psi300_crit):
        print("UNKNOWN - psi300_warn must be < psi300_crit")
        return EXIT_UNK

    # ========================================================================
    # LOCKING
    # ========================================================================

    # Acquire lock to prevent concurrent executions
    # This ensures rate calculations are accurate
    lock_fd = None
    if not args.no_lock:
        lock_fd = flock_nowait(args.lock_file)
        if not lock_fd:
            if args.high_freq:
                # In high-frequency mode, skip this check instead of failing
                # This prevents cascading failures if one check runs long
                return EXIT_OK
            print("UNKNOWN - Could not acquire lock (another instance running?)")
            return EXIT_UNK

    # Ensure lock is released on early returns below
    def _cleanup_lock():
        if lock_fd:
            try:
                os.close(lock_fd)
            except Exception:
                pass

    # Check if we should exit gracefully
    if graceful.exit_now:
        _cleanup_lock()
        return EXIT_OK

    # ========================================================================
    # DATA COLLECTION
    # ========================================================================

    # Record start time for performance measurement
    t0 = time.time()

    # Collect all metrics in parallel for efficiency
    # These operations are very fast (<1ms each)

    # 1. Memory statistics from /proc/meminfo
    mi = parse_meminfo_fast()
    if 'MemTotal' not in mi:
        print("UNKNOWN - Cannot read MemTotal from /proc/meminfo")
        _cleanup_lock()
        return EXIT_UNK

    # 2. VM statistics from /proc/vmstat (for swap/fault rates)
    vm = parse_vmstat_fast()

    # 3. PSI (Pressure) metrics if available
    psi_ok, psi10, psi60, psi300 = read_psi_fast()

    # ========================================================================
    # CALCULATE PRIMARY METRICS
    # ========================================================================

    # Extract key memory values (all in KB)
    mem_total = mi['MemTotal']

    # MemAvailable is the kernel's estimate of how much memory is available
    # for starting new applications, without swapping
    mem_avail = mi.get('MemAvailable')
    if mem_avail is None:
        # Fallback for older kernels without MemAvailable
        # This is less accurate but better than nothing
        mem_avail = mi.get('MemFree', 0) + mi.get('Buffers', 0) + mi.get('Cached', 0)

    # Swap statistics
    swap_total = mi.get('SwapTotal', 0)
    swap_free = mi.get('SwapFree', 0)

    # Calculate percentages
    mem_avail_pct = (mem_avail * 100.0 / mem_total) if mem_total else 0.0
    swap_used_pct = ((swap_total - swap_free) * 100.0 / swap_total) if swap_total else 0.0

    # ========================================================================
    # RATE CALCULATIONS
    # ========================================================================

    # Read previous state to calculate rates
    # Rates are important because they show active memory pressure
    # High swap usage alone doesn't mean the system is swapping NOW

    state_mgr = StateManager(args.state_file)
    prev = state_mgr.read() if not args.high_freq else {}

    now_ts = int(t0)
    prev_ts = prev.get('ts')
    first_run = prev_ts is None
    dt = max(1, now_ts - (prev_ts if prev_ts is not None else now_ts - 1))

    # Calculate rates (pages/second)
    prev_vm = prev.get('vm', {})
    pswpin_s     = max(0, (vm.get('pswpin', 0)     - prev_vm.get('pswpin', 0))     / dt)
    pswpout_s    = max(0, (vm.get('pswpout', 0)    - prev_vm.get('pswpout', 0))    / dt)
    pgmajfault_s = max(0, (vm.get('pgmajfault', 0) - prev_vm.get('pgmajfault', 0)) / dt)

    # Smooth the first sample to avoid misleading spikes
    if first_run:
        pswpin_s = pswpout_s = pgmajfault_s = 0.0

    # ========================================================================
    # OPTIONAL CHECKS
    # ========================================================================

    # Check memory fragmentation if requested
    fragmentation_score = 0
    if args.check_fragmentation:
        fragmentation_score = check_memory_fragmentation()

    # Check NUMA balance if requested
    numa_info = None
    numa_state = EXIT_OK
    if args.check_numa:
        node, pct, numa_state = numa_check_fast(args.numa_warn, args.numa_crit)
        if node:
            numa_info = {'node': node, 'pct': round(pct, 2)}

    # ========================================================================
    # STATE PERSISTENCE
    # ========================================================================

    # Save current state for next execution
    # This enables rate calculations on the next run
    if not args.high_freq:
        state_mgr.write({'ts': now_ts, 'vm': vm})

    # ========================================================================
    # BUILD METRICS DICTIONARY
    # ========================================================================

    # Collect all metrics in a structured format
    metrics = {
        'mem_avail_pct': round(mem_avail_pct, 2),
        'swap_used_pct': round(swap_used_pct, 2),
        'psi10_pct': round(psi10, 2) if psi10 is not None else None,
        'psi60_pct': round(psi60, 2) if psi60 is not None else None,
        'psi300_pct': round(psi300, 2) if psi300 is not None else None,
        'pswpin_per_s': round(pswpin_s, 2),
        'pswpout_per_s': round(pswpout_s, 2),
        'pgmajfault_per_s': round(pgmajfault_s, 2),
        'fragmentation_pct': round(fragmentation_score, 2) if args.check_fragmentation else None,
        'ts': now_ts,
        'check_ms': round((time.time() - t0) * 1000, 2)  # Performance metric
    }

    # ========================================================================
    # HISTORY UPDATE
    # ========================================================================

    # Update historical metrics for long-term trending
    if not args.no_history:
        history = AsyncHistoryWriter(args.history_file, args.advise_interval_hours)
        history.queue_update(metrics, t0)

        # Only write to disk periodically to reduce I/O
        if history.should_update(t0):
            history.flush(args.advise_window_days)

    # ========================================================================
    # THRESHOLD EVALUATION
    # ========================================================================

    # Determine overall health state based on all metrics
    state = EXIT_OK
    reasons = []  # Track why we're warning/critical

    # Check 1: Basic memory availability
    if mem_avail_pct <= args.mem_crit:
        state = EXIT_CRIT
        reasons.append(f"MemAvail≤{args.mem_crit}%")
    elif mem_avail_pct <= args.mem_warn:
        state = EXIT_WARN
        reasons.append(f"MemAvail≤{args.mem_warn}%")

    # Check 2: PSI (Pressure) thresholds
    # PSI indicates the percentage of time tasks were stalled waiting for memory
    # This is often a better indicator than raw memory usage

    if psi_ok and psi10 is not None:
        # Short-term pressure (10-second average)
        if psi10 >= args.psi10_crit:
            # Critical if also swapping or very low memory
            if pswpin_s >= args.swapin_crit or mem_avail_pct <= 5:
                state = EXIT_CRIT
                reasons.append(f"PSI10≥{args.psi10_crit}%+swap")
        elif psi10 >= args.psi10_warn:
            # Warning if also some swapping or low memory
            if pswpin_s >= args.swapin_warn or mem_avail_pct <= 10:
                state = max(state, EXIT_WARN)
                reasons.append(f"PSI10≥{args.psi10_warn}%")

    if psi_ok and psi300 is not None:
        # Long-term pressure (5-minute average)
        # This indicates sustained memory pressure
        if psi300 >= args.psi300_crit:
            state = EXIT_CRIT
            reasons.append(f"PSI300≥{args.psi300_crit}%")
        elif psi300 >= args.psi300_warn:
            state = max(state, EXIT_WARN)
            reasons.append(f"PSI300≥{args.psi300_warn}%")

    # Check 3: Active swapping
    # Note: We check swap RATE, not just usage
    # A system can have high swap usage but no current swapping (OK)
    # Or low swap usage but active swapping (BAD)

    if pswpin_s >= args.swapin_crit:
        state = EXIT_CRIT
        reasons.append(f"SwapIn≥{args.swapin_crit}/s")
    elif pswpin_s >= args.swapin_warn:
        state = max(state, EXIT_WARN)
        reasons.append(f"SwapIn≥{args.swapin_warn}/s")

    # Check 4: NUMA imbalance
    if numa_state != EXIT_OK:
        state = max(state, numa_state)
        if numa_info:
            reasons.append(f"NUMA_{numa_info['node']}={numa_info['pct']:.1f}%")

    # ========================================================================
    # FIND MEMORY HOG (if degraded)
    # ========================================================================

    # Only look for the culprit if we're in a bad state
    # This avoids overhead during normal operation
    offender = None
    if args.find_offender and state != EXIT_OK:
        cmd, kb = find_swap_offender_fast(args.offender_threshold)
        if cmd:
            offender = {'cmd': cmd[:50], 'swap_kb': kb}
            reasons.append(f"Swap:{cmd[:20]}({kb//1024}M)")

    # ========================================================================
    # GENERATE ADVICE (if requested)
    # ========================================================================

    advice = None
    if args.advise and not args.no_history:
        # Load historical data
        hist_rows = []
        try:
            with open(args.history_file, 'r') as f:
                for line in f:
                    try:
                        hist_rows.append(json.loads(line))
                    except:
                        continue
        except FileNotFoundError:
            pass

        # Generate advice based on patterns
        if hist_rows:
            advice = generate_advice(hist_rows, args.advise_min_buckets)

    # ========================================================================
    # OUTPUT FORMATTING
    # ========================================================================

    # Convert state to text
    state_text = ["OK", "WARNING", "CRITICAL", "UNKNOWN"][state]

    # RAW mode - minimal JSON for high-frequency collection
    if mode == "raw":
        output = {'s': state, 'm': metrics, 'r': reasons[:3] if reasons else None}
        if offender:
            output['o'] = offender
        print(json.dumps(output, separators=(',', ':')))
        _cleanup_lock()
        return state

    # Build human-readable message
    msg_parts = [state_text, f"MemAvail={int(mem_avail_pct)}%"]
    if psi10 is not None:
        msg_parts.append(f"PSI10={int(psi10)}%")
    if psi300 is not None:
        msg_parts.append(f"PSI300={int(psi300)}%")

    msg_parts.append(f"SwapIn={pswpin_s:.1f}/s")

    if reasons:
        msg_parts.append(f"[{'; '.join(reasons[:2])}]")

    if advice:
        msg_parts.append(f"Advice: {advice}")

    msg = " ".join(msg_parts)

    # Build performance data (for graphing)
    perf = [
        f"mem_avail_pct={metrics['mem_avail_pct']}%;;;0;100",
        f"swap_used_pct={metrics['swap_used_pct']}%;;;0;100",
    ]

    if psi10 is not None:
        perf.append(f"psi10_pct={metrics['psi10_pct']}%;;;0;100")
    if psi60 is not None:
        perf.append(f"psi60_pct={metrics['psi60_pct']}%;;;0;100")
    if psi300 is not None:
        perf.append(f"psi300_pct={metrics['psi300_pct']}%;;;0;100")

    perf.extend([
        f"pswpin_per_s={metrics['pswpin_per_s']}",
        f"pswpout_per_s={metrics['pswpout_per_s']}",
        f"pgmajfault_per_s={metrics['pgmajfault_per_s']}",
        f"check_time_ms={metrics['check_ms']}ms;;;0;1000"
    ])

    if args.check_fragmentation and metrics['fragmentation_pct'] is not None:
        perf.append(f"fragmentation={metrics['fragmentation_pct']}%;;;0;100")

    # Format output based on mode

    if mode == "zabbix":
        output = {'state': state_text, 'state_code': state, 'metrics': metrics, 'message': msg}
        if advice:
            output['advice'] = advice
        print(json.dumps(output, separators=(',', ':')))

    elif mode == "prom":
        # Prometheus text exposition format
        lines = []
        for key, val in metrics.items():
            if val is not None and key not in ('ts', 'check_ms'):
                lines.append(f"mem_health_{key} {val}")
        lines.append(f"mem_health_state {state}")
        print('\n'.join(lines))

    elif mode == "checkmk":
        # Check_MK local check format
        print(f"{state} mem_health - {msg} | {' '.join(perf)}")
    else:  # nagios/icinga
        print(f"{msg} | {' '.join(perf)}")

    _cleanup_lock()
    return state

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    """
    Script entry point with exception handling.

    Ensures clean exit codes for monitoring systems even on errors.
    """
    try:
        # Run main function and exit with appropriate code
        sys.exit(main())
    except KeyboardInterrupt:
        # Handle Ctrl-C gracefully
        print("\nInterrupted by user")
        sys.exit(EXIT_UNK)
    except Exception as e:
        # Catch any unexpected errors
        # This ensures monitoring systems get a proper status
        print(f"UNKNOWN - Unexpected error: {e}")
        sys.exit(EXIT_UNK)
