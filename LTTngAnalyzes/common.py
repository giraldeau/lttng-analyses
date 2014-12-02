import math
import time
import os
import socket

NSEC_PER_SEC = 1000000000
MSEC_PER_NSEC = 1000000

O_CLOEXEC = 0o2000000

# approximation for the progress bar
BYTES_PER_EVENT = 30


class Process():
    def __init__(self):
        self.tid = -1
        self.pid = -1
        self.comm = ""
        self.cpu_ns = 0
        self.migrate_count = 0
        # network read/write
        self.net_read = 0
        self.net_write = 0
        # disk read/write (might be cached)
        self.disk_read = 0
        self.disk_write = 0
        # actual block access read/write
        self.block_read = 0
        self.block_write = 0
        # unclassified read/write (FD passing and statedump)
        self.unk_read = 0
        self.unk_write = 0
        # total I/O read/write
        self.read = 0
        self.write = 0
        # last TS where the process was scheduled in
        self.last_sched = 0
        # the process scheduled before this one
        self.prev_tid = -1
        # indexed by syscall_name
        self.syscalls = {}
        # indexed by fd
        self.fds = {}
        # indexed by filename
        self.closed_fds = {}
        self.current_syscall = {}
        self.perf = {}
        self.dirty = 0
        self.allocated_pages = 0
        self.freed_pages = 0
        self.total_syscalls = 0


class CPU():
    def __init__(self):
        self.cpu_id = -1
        self.cpu_ns = 0
        self.current_tid = -1
        self.start_task_ns = 0
        self.perf = {}
        self.wakeup_queue = []


class Syscall():
    def __init__(self):
        self.name = ""
        self.count = 0


class Disk():
    def __init__(self):
        self.name = ""
        self.prettyname = ""
        self.nr_sector = 0
        self.nr_requests = 0
        self.completed_requests = 0
        self.request_time = 0
        self.pending_requests = {}


class Iface():
    def __init__(self):
        self.name = ""
        self.recv_bytes = 0
        self.recv_packets = 0
        self.send_bytes = 0
        self.send_packets = 0


class FDType():
    unknown = 0
    disk = 1
    net = 2
    # not 100% sure they are network FDs (assumed when net_dev_xmit is
    # called during a write syscall and the type in unknown).
    maybe_net = 3


class FD():
    def __init__(self):
        self.filename = ""
        self.fd = -1
        # network read/write
        self.net_read = 0
        self.net_write = 0
        # address family
        self.family = socket.AF_UNSPEC
        # disk read/write (might be cached)
        self.disk_read = 0
        self.disk_write = 0
        # unclassified read/write (FD passing and statedump)
        self.unk_read = 0
        self.unk_write = 0
        # total read/write
        self.read = 0
        self.write = 0
        self.open = 0
        self.close = 0
        self.cloexec = 0
        self.fdtype = FDType.unknown
        # if FD was inherited, parent PID
        self.parent = -1


class IRQ():
    HARD_IRQ = 1
    SOFT_IRQ = 2
    # from include/linux/interrupt.h
    soft_names = {0: "HI_SOFTIRQ",
                  1: "TIMER_SOFTIRQ",
                  2: "NET_TX_SOFTIRQ",
                  3: "NET_RX_SOFTIRQ",
                  4: "BLOCK_SOFTIRQ",
                  5: "BLOCK_IOPOLL_SOFTIRQ",
                  6: "TASKLET_SOFTIRQ",
                  7: "SCHED_SOFTIRQ",
                  8: "HRTIMER_SOFTIRQ",
                  9: "RCU_SOFTIRQ"}

    def __init__(self):
        self.nr = -1
        self.irqclass = 0
        self.start_ts = -1
        self.stop_ts = -1
        self.raise_ts = -1
        self.cpu_id = -1


# imported from include/linux/kdev_t.h
def kdev_major_minor(dev):
    MINORBITS = 20
    MINORMASK = ((1 << MINORBITS) - 1)
    major = dev >> MINORBITS
    minor = dev & MINORMASK
    return "(%d,%d)" % (major, minor)


def get_disk(dev, disks):
    if dev not in disks:
        d = Disk()
        d.name = "%d" % dev
        d.prettyname = kdev_major_minor(dev)
        disks[dev] = d
    else:
        d = disks[dev]
    return d


def convert_size(size):
    if size <= 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size, 1024)))
    p = math.pow(1024, i)
    s = round(size/p, 2)
    if (s > 0):
        try:
            return '%s %s' % (s, size_name[i])
        except:
            print(i, size_name)
            raise Exception("Too big to be true")
    else:
        return '0 B'


def ns_to_asctime(ns):
    return time.asctime(time.localtime(ns/NSEC_PER_SEC))


def ns_to_hour(ns):
    d = time.localtime(ns/NSEC_PER_SEC)
    return "%02d:%02d:%02d" % (d.tm_hour, d.tm_min, d.tm_sec)


def ns_to_hour_nsec(ns):
    d = time.localtime(ns/NSEC_PER_SEC)
    return "%02d:%02d:%02d.%09d" % (d.tm_hour, d.tm_min, d.tm_sec,
                                    ns % NSEC_PER_SEC)


def ns_to_sec(ns):
    return "%lu.%09u" % (ns/NSEC_PER_SEC, ns % NSEC_PER_SEC)


def sec_to_hour(ns):
    d = time.localtime(ns)
    return "%02d:%02d:%02d" % (d.tm_hour, d.tm_min, d.tm_sec)


def sec_to_nsec(sec):
    return sec * NSEC_PER_SEC


def getFolderSize(folder):
    total_size = os.path.getsize(folder)
    for item in os.listdir(folder):
        itempath = os.path.join(folder, item)
        if os.path.isfile(itempath):
            total_size += os.path.getsize(itempath)
        elif os.path.isdir(itempath):
            total_size += getFolderSize(itempath)
    return total_size


def seq_to_ipv4(ip):
    return "{}.{}.{}.{}".format(ip[0], ip[1], ip[2], ip[3])
