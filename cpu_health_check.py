#!/usr/bin/env python3
"""
cpu_health_check.py — CPU health check for Linux
"""

import os
import re
import sys
import time
import json
import argparse
from typing import Dict, Any, Tuple, Optional, List

# Previous imports and constants remain the same
EXIT_OK, EXIT_WARN, EXIT_CRIT, EXIT_UNK = 0, 1, 2, 3

# ============================================================================
# VM DETECTION AND METRICS
# ============================================================================

def detect_virtualization() -> Dict[str, Any]:
    """
    Detect if running in a VM and identify the hypervisor.

    Returns:
        Dictionary with VM information
    """
    vm_info = {
        'is_vm': False,
        'hypervisor': None,
        'vm_type': None,
        'features': []
    }

    # Method 1: Check systemd-detect-virt (most reliable)
    try:
        import subprocess
        result = subprocess.run(['systemd-detect-virt'],
                              capture_output=True, text=True, timeout=1)
        if result.returncode == 0:
            virt_type = result.stdout.strip()
            if virt_type != 'none':
                vm_info['is_vm'] = True
                vm_info['hypervisor'] = virt_type
    except:
        pass

    # Method 2: Check DMI/SMBIOS
    try:
        with open('/sys/class/dmi/id/sys_vendor', 'r') as f:
            vendor = f.read().strip().lower()
            if 'vmware' in vendor:
                vm_info['is_vm'] = True
                vm_info['hypervisor'] = 'vmware'
            elif 'nutanix' in vendor or 'ahv' in vendor:
                vm_info['is_vm'] = True
                vm_info['hypervisor'] = 'nutanix-ahv'
            elif 'xen' in vendor:
                vm_info['is_vm'] = True
                vm_info['hypervisor'] = 'xen'
            elif 'kvm' in vendor or 'qemu' in vendor:
                vm_info['is_vm'] = True
                vm_info['hypervisor'] = 'kvm'
            elif 'microsoft' in vendor:
                vm_info['is_vm'] = True
                vm_info['hypervisor'] = 'hyperv'
    except:
        pass

    # Method 3: Check /proc/cpuinfo for hypervisor flag
    try:
        with open('/proc/cpuinfo', 'r') as f:
            cpuinfo = f.read()
            if 'hypervisor' in cpuinfo:
                vm_info['is_vm'] = True
                if not vm_info['hypervisor']:
                    vm_info['hypervisor'] = 'unknown'
    except:
        pass

    # Method 4: Check for VM-specific files/drivers
    vm_indicators = {
        '/dev/vmci': 'vmware',
        '/sys/bus/vmbus': 'hyperv',
        '/dev/xen': 'xen',
        '/dev/virtio-ports': 'kvm',
        '/sys/devices/virtual/dmi/id/product_name': 'check_product'
    }

    for path, platform in vm_indicators.items():
        if os.path.exists(path):
            vm_info['is_vm'] = True
            if platform != 'check_product':
                vm_info['hypervisor'] = platform
            else:
                try:
                    with open(path, 'r') as f:
                        product = f.read().strip().lower()
                        if 'vmware' in product:
                            vm_info['hypervisor'] = 'vmware'
                        elif 'virtualbox' in product:
                            vm_info['hypervisor'] = 'virtualbox'
                        elif 'ahv' in product or 'nutanix' in product:
                            vm_info['hypervisor'] = 'nutanix-ahv'
                except:
                    pass

    # Check for VMware tools
    if os.path.exists('/usr/bin/vmware-toolbox-cmd'):
        vm_info['is_vm'] = True
        vm_info['hypervisor'] = 'vmware'
        vm_info['features'].append('vmware-tools')

    # Check for qemu guest agent
    if os.path.exists('/usr/bin/qemu-ga'):
        vm_info['is_vm'] = True
        if not vm_info['hypervisor']:
            vm_info['hypervisor'] = 'kvm'
        vm_info['features'].append('qemu-ga')

    return vm_info

def get_cpu_steal_time(cpu_stats: Dict[str, Any], prev_stats: Dict[str, Any], dt: float) -> float:
    """
    Calculate CPU steal time percentage.

    Steal time is the percentage of time the virtual CPU is ready to run
    but the hypervisor is servicing another VM.

    Args:
        cpu_stats: Current CPU statistics
        prev_stats: Previous CPU statistics
        dt: Time delta in seconds

    Returns:
        Steal time percentage (0-100)
    """
    if not prev_stats or dt <= 0:
        return 0.0

    curr_cpu = cpu_stats.get('cpus', {}).get('cpu_all', {})
    prev_cpu = prev_stats.get('cpu_all', {})

    if not curr_cpu or not prev_cpu:
        return 0.0

    # Get steal time from stats (8th field in /proc/stat)
    curr_steal = curr_cpu.get('steal', 0)
    prev_steal = prev_cpu.get('steal', 0)

    curr_total = curr_cpu.get('total', 0)
    prev_total = prev_cpu.get('total', 0)

    steal_delta = curr_steal - prev_steal
    total_delta = curr_total - prev_total

    if total_delta <= 0:
        return 0.0

    steal_pct = (steal_delta / total_delta) * 100.0
    return min(100.0, max(0.0, steal_pct))

def parse_cpu_stat_with_steal() -> Dict[str, Any]:
    """
    Enhanced CPU stat parsing that includes steal time.
    """
    data = read_file_mmap('/proc/stat')

    cpu_stats = {}

    # Updated regex to capture steal time (8th field)
    re_cpu_with_steal = re.compile(
        rb'^cpu(\d*)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)?',
        re.MULTILINE
    )

    for match in re_cpu_with_steal.findall(data):
        cpu_id = match[0].decode() if match[0] else 'all'

        # CPU time components (in jiffies)
        user = int(match[1])
        nice = int(match[2])
        system = int(match[3])
        idle = int(match[4])
        iowait = int(match[5])
        irq = int(match[6])
        softirq = int(match[7])
        steal = int(match[8]) if match[8] else 0  # Steal time (VM environments)

        total = user + nice + system + idle + iowait + irq + softirq + steal
        busy = total - idle - iowait  # Non-idle time (including steal)

        cpu_stats[f'cpu_{cpu_id}'] = {
            'user': user,
            'nice': nice,
            'system': system,
            'idle': idle,
            'iowait': iowait,
            'irq': irq,
            'softirq': softirq,
            'steal': steal,  # Important for VMs
            'total': total,
            'busy': busy
        }

    # Extract other metrics
    stats = {'cpus': cpu_stats}

    for line in data.split(b'\n'):
        if line.startswith(b'ctxt '):
            stats['ctxt'] = int(line.split()[1])
        elif line.startswith(b'processes '):
            stats['processes'] = int(line.split()[1])
        elif line.startswith(b'procs_running '):
            stats['procs_running'] = int(line.split()[1])
        elif line.startswith(b'procs_blocked '):
            stats['procs_blocked'] = int(line.split()[1])

    return stats

def get_vm_specific_metrics(vm_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Collect VM-specific metrics based on hypervisor type.
    """
    metrics = {}

    if vm_info['hypervisor'] == 'vmware':
        # Try to get VMware-specific metrics
        try:
            import subprocess
            # Check if vmware-toolbox-cmd is available
            result = subprocess.run(
                ['vmware-toolbox-cmd', 'stat', 'raw', 'text', 'cpu'],
                capture_output=True, text=True, timeout=1
            )
            if result.returncode == 0:
                # Parse VMware CPU stats
                for line in result.stdout.split('\n'):
                    if 'cpu.reservationMHz' in line:
                        metrics['cpu_reservation_mhz'] = int(line.split()[-1])
                    elif 'cpu.limitMHz' in line:
                        metrics['cpu_limit_mhz'] = int(line.split()[-1])
        except:
            pass

    elif vm_info['hypervisor'] in ['kvm', 'nutanix-ahv']:
        # Check for CPU hotplug capability
        try:
            if os.path.exists('/sys/devices/system/cpu/cpu0/online'):
                metrics['cpu_hotplug'] = True
        except:
            pass

    return metrics

def calculate_vm_adjusted_thresholds(base_threshold: float, steal_pct: float) -> float:
    """
    Adjust thresholds based on CPU steal time.

    In VMs, high steal time means the hypervisor is busy, so we should
    be more tolerant of what appears to be high CPU usage.
    """
    # If steal time is high, adjust threshold upward
    # For every 10% steal, add 5% tolerance
    adjustment = (steal_pct / 10) * 5
    return min(100, base_threshold + adjustment)

# ============================================================================
# ENHANCED MAIN FUNCTION FOR VMs
# ============================================================================

def main_vm_aware():
    """Enhanced main function with VM awareness."""

    # Parse arguments
    args = parse_args()

    # Detect virtualization
    vm_info = detect_virtualization()

    # Adjust behavior for VMs
    if vm_info['is_vm']:
        # Disable physical-only features
        if args.check_thermal:
            if args.debug:
                print(f"INFO: Disabling thermal check (VM detected: {vm_info['hypervisor']})")
            args.check_thermal = False

        if args.check_frequency:
            if args.debug:
                print(f"INFO: Disabling frequency check (VM detected: {vm_info['hypervisor']})")
            args.check_frequency = False

    # Start monitoring
    t0 = time.time()

    # Get CPU count (will be vCPUs in VM)
    cpu_count = get_cpu_count()

    # Parse CPU statistics with steal time
    cpu_stats = parse_cpu_stat_with_steal()

    # Get load average
    load1, load5, load15, running, total_threads = parse_loadavg()

    # Get PSI if available (still meaningful in VMs)
    psi_ok, psi10, psi60, psi300 = read_psi_cpu()

    # Read previous state for rate calculations
    state_mgr = StateManager(args.state_file)
    prev = state_mgr.read()

    now_ts = int(t0)
    dt = max(1, now_ts - prev.get('ts', now_ts - 1))

    # Calculate CPU usage and steal time
    prev_cpu_all = prev.get('cpu_all', {})
    curr_cpu_all = cpu_stats['cpus'].get('cpu_all', {})
    cpu_usage_pct = calculate_cpu_usage(prev_cpu_all, curr_cpu_all, dt)
    steal_pct = get_cpu_steal_time(cpu_stats, prev, dt)

    # Calculate other rates
    prev_ctxt = prev.get('ctxt', 0)
    curr_ctxt = cpu_stats.get('ctxt', 0)
    ctxt_per_s = max(0, (curr_ctxt - prev_ctxt) / dt)

    # Get VM-specific metrics
    vm_metrics = {}
    if vm_info['is_vm']:
        vm_metrics = get_vm_specific_metrics(vm_info)

    # Build metrics dictionary
    metrics = {
        'cpu_usage_pct': round(cpu_usage_pct, 2),
        'cpu_steal_pct': round(steal_pct, 2),  # Important for VMs
        'cpu_count': cpu_count,
        'load1': round(load1, 2),
        'load5': round(load5, 2),
        'load15': round(load15, 2),
        'load1_per_cpu': round(load1 / cpu_count, 2),
        'psi10_pct': round(psi10, 2) if psi10 is not None else None,
        'psi300_pct': round(psi300, 2) if psi300 is not None else None,
        'ctxt_per_s': round(ctxt_per_s, 2),
        'is_vm': vm_info['is_vm'],
        'hypervisor': vm_info['hypervisor'],
        'ts': now_ts
    }

    # Add VM-specific metrics
    metrics.update(vm_metrics)

    # ========================================================================
    # VM-AWARE THRESHOLD EVALUATION
    # ========================================================================

    state = EXIT_OK
    reasons = []

    # Adjust CPU threshold if steal time is significant
    effective_cpu_warn = args.cpu_warn
    effective_cpu_crit = args.cpu_crit

    if steal_pct > 5:  # More than 5% steal is significant
        effective_cpu_warn = calculate_vm_adjusted_thresholds(args.cpu_warn, steal_pct)
        effective_cpu_crit = calculate_vm_adjusted_thresholds(args.cpu_crit, steal_pct)

        # Add steal time to reasons if high
        if steal_pct >= 20:
            state = EXIT_CRIT
            reasons.append(f"Steal≥20% (hypervisor busy)")
        elif steal_pct >= 10:
            state = EXIT_WARN
            reasons.append(f"Steal≥10% (hypervisor contention)")

    # CPU usage check with adjusted thresholds
    if cpu_usage_pct >= effective_cpu_crit:
        state = EXIT_CRIT
        reasons.append(f"CPU≥{args.cpu_crit}%")
    elif cpu_usage_pct >= effective_cpu_warn:
        state = max(state, EXIT_WARN)
        reasons.append(f"CPU≥{args.cpu_warn}%")

    # Load check (adjust for VMs as vCPUs may be overcommitted)
    if vm_info['is_vm']:
        # Be more tolerant of high load in VMs
        load_warn = cpu_count * (args.load_warn_mult * 1.5)  # 50% more tolerance
        load_crit = cpu_count * (args.load_crit_mult * 1.5)
    else:
        load_warn = cpu_count * args.load_warn_mult
        load_crit = cpu_count * args.load_crit_mult

    if load1 >= load_crit:
        state = EXIT_CRIT
        reasons.append(f"Load≥{load_crit:.1f}")
    elif load1 >= load_warn:
        state = max(state, EXIT_WARN)
        reasons.append(f"Load≥{load_warn:.1f}")

    # PSI checks (still relevant in VMs)
    if psi_ok and psi10 is not None:
        # Adjust PSI thresholds for VMs (they naturally have higher PSI)
        psi10_warn = args.psi10_warn * 1.2 if vm_info['is_vm'] else args.psi10_warn
        psi10_crit = args.psi10_crit * 1.2 if vm_info['is_vm'] else args.psi10_crit

        if psi10 >= psi10_crit:
            state = EXIT_CRIT
            reasons.append(f"PSI10≥{psi10_crit:.0f}%")
        elif psi10 >= psi10_warn:
            state = max(state, EXIT_WARN)
            reasons.append(f"PSI10≥{psi10_warn:.0f}%")

    # ========================================================================
    # VM-SPECIFIC ADVICE
    # ========================================================================

    advice = None
    if vm_info['is_vm'] and state != EXIT_OK:
        if steal_pct > 15:
            advice = f"High CPU steal ({steal_pct:.1f}%) indicates hypervisor contention. Consider: 1) Request CPU reservation, 2) Move to less busy host, 3) Check for noisy neighbors"
        elif cpu_usage_pct > 90 and steal_pct < 5:
            advice = "High CPU usage with low steal. Consider: 1) Add more vCPUs, 2) Optimize application, 3) Check for CPU limits"
        elif load1 > cpu_count * 2:
            advice = f"High load ({load1:.1f}) for {cpu_count} vCPUs. Consider: 1) Add vCPUs if possible, 2) Check for I/O bottlenecks"

    # ========================================================================
    # OUTPUT FORMATTING
    # ========================================================================

    state_text = ["OK", "WARNING", "CRITICAL", "UNKNOWN"][state]

    # Build message
    msg_parts = [state_text]

    if vm_info['is_vm']:
        msg_parts.append(f"[VM:{vm_info['hypervisor']}]")

    msg_parts.append(f"CPU={int(cpu_usage_pct)}%")

    if steal_pct > 1:  # Only show steal if significant
        msg_parts.append(f"Steal={int(steal_pct)}%")

    msg_parts.append(f"Load={load1:.2f}")

    if psi10 is not None:
        msg_parts.append(f"PSI10={int(psi10)}%")

    if reasons:
        msg_parts.append(f"[{'; '.join(reasons[:2])}]")

    if advice:
        msg_parts.append(f"Advice: {advice}")

    msg = " ".join(msg_parts)

    # Build performance data
    perf = [
        f"cpu_usage_pct={metrics['cpu_usage_pct']}%;;;0;100",
        f"cpu_steal_pct={metrics['cpu_steal_pct']}%;;;0;100",
        f"load1={metrics['load1']};;;0;{cpu_count*3}",
        f"load1_per_cpu={metrics['load1_per_cpu']};;;0;3"
    ]

    if psi10 is not None:
        perf.append(f"psi10_pct={metrics['psi10_pct']}%;;;0;100")

    perf.append(f"ctxt_per_s={metrics['ctxt_per_s']}")

    # Output
    if args.raw:
        output = {
            's': state,
            'm': metrics,
            'r': reasons[:3] if reasons else None,
            'vm': vm_info
        }
        print(json.dumps(output, separators=(',', ':')))
    else:
        print(f"{msg} | {' '.join(perf)}")

    return state

# ============================================================================
# VM-SPECIFIC HELPER FUNCTIONS
# ============================================================================

def read_file_mmap(path: str) -> bytes:
    """Read file using memory-mapped I/O."""
    try:
        with open(path, 'rb') as f:
            if os.path.getsize(path) == 0:
                return b''
            import mmap
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                return bytes(m)
    except:
        with open(path, 'rb') as f:
            return f.read()

def parse_loadavg() -> Tuple[float, float, float, int, int]:
    """Parse /proc/loadavg."""
    try:
        with open('/proc/loadavg', 'r') as f:
            parts = f.read().split()
            return (float(parts[0]), float(parts[1]), float(parts[2]),
                   int(parts[3].split('/')[0]), int(parts[3].split('/')[1]))
    except:
        return 0.0, 0.0, 0.0, 0, 0

def read_psi_cpu() -> Tuple[bool, Optional[float], Optional[float], Optional[float]]:
    """Read CPU PSI metrics."""
    try:
        with open('/proc/pressure/cpu', 'r') as f:
            for line in f:
                if line.startswith('some'):
                    parts = line.split()
                    avg10 = float(parts[1].split('=')[1])
                    avg60 = float(parts[2].split('=')[1])
                    avg300 = float(parts[3].split('=')[1])
                    return True, avg10, avg60, avg300
    except:
        pass
    return False, None, None, None

def get_cpu_count() -> int:
    """Get CPU count."""
    try:
        return os.cpu_count() or 1
    except:
        return 1

def calculate_cpu_usage(prev_cpu: Dict, curr_cpu: Dict, dt: float) -> float:
    """Calculate CPU usage percentage."""
    if not prev_cpu or dt <= 0:
        return 0.0

    prev_total = prev_cpu.get('total', 0)
    curr_total = curr_cpu.get('total', 0)
    prev_busy = prev_cpu.get('busy', 0)
    curr_busy = curr_cpu.get('busy', 0)

    total_delta = curr_total - prev_total
    busy_delta = curr_busy - prev_busy

    if total_delta <= 0:
        return 0.0

    return min(100.0, (busy_delta / total_delta) * 100.0)

class StateManager:
    """Simple state management."""
    def __init__(self, path: str):
        self.path = path

    def read(self) -> Dict:
        try:
            with open(self.path, 'r') as f:
                return json.load(f)
        except:
            return {}

    def write(self, data: Dict):
        with open(self.path, 'w') as f:
            json.dump(data, f)

def parse_args():
    """Parse command-line arguments."""
    ap = argparse.ArgumentParser(description="VM-aware CPU health check")

    # Basic thresholds
    ap.add_argument("--cpu-warn", type=float, default=80.0, help="CPU warning threshold")
    ap.add_argument("--cpu-crit", type=float, default=95.0, help="CPU critical threshold")
    ap.add_argument("--load-warn-mult", type=float, default=1.5, help="Load warning multiplier")
    ap.add_argument("--load-crit-mult", type=float, default=3.0, help="Load critical multiplier")
    ap.add_argument("--psi10-warn", type=float, default=20.0, help="PSI avg10 warning")
    ap.add_argument("--psi10-crit", type=float, default=50.0, help="PSI avg10 critical")

    # VM-specific options
    ap.add_argument("--steal-warn", type=float, default=10.0, help="CPU steal warning")
    ap.add_argument("--steal-crit", type=float, default=20.0, help="CPU steal critical")
    ap.add_argument("--vm-auto-adjust", action="store_true", help="Auto-adjust thresholds for VMs")

    # Features (some disabled in VMs)
    ap.add_argument("--check-thermal", action="store_true", help="Check thermal (disabled in VMs)")
    ap.add_argument("--check-frequency", action="store_true", help="Check frequency (disabled in VMs)")

    # Output options
    ap.add_argument("--raw", action="store_true", help="Raw JSON output")
    ap.add_argument("--debug", action="store_true", help="Debug output")

    # Files
    ap.add_argument("--state-file", default="/dev/shm/cpu_health.state", help="State file path")

    return ap.parse_args()

if __name__ == "__main__":
    try:
        sys.exit(main_vm_aware())
    except Exception as e:
        print(f"UNKNOWN - {e}")
        sys.exit(EXIT_UNK)
