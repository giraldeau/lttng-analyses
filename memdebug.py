#!/usr/bin/env python3

import sys
import time
import argparse
import pprint

NSEC_PER_SEC = 1000000000

try:
    from babeltrace import TraceCollection
except ImportError:
    # quick fix for debian-based distros
    sys.path.append("/usr/local/lib/python%d.%d/site-packages" %
                    (sys.version_info.major, sys.version_info.minor))
    from babeltrace import TraceCollection

sys.path.append("/home/francis/gitsrc/lttng-analyses")

class TraceParser:
    def __init__(self, trace, kas = None, log_file = sys.stdout):
        self.trace = trace
        if not kas:
            kas = Kallsyms()
        self.kas = kas
        self.event_count = {}
        self.current = {}
        self.pages = {}
        self.leaks = {}
        self.error_alloc = []
        self.error_free = []
        self.matches = []
        self.matches_count = 0
        self.softirq = {}
        self.log = log_file

    def ns_to_hour_nsec(self, ns):
        d = time.localtime(ns/NSEC_PER_SEC)
        return "%02d:%02d:%02d.%09d" % (d.tm_hour, d.tm_min, d.tm_sec,
                                        ns % NSEC_PER_SEC)

    def parse(self):
        # iterate over all the events
        method_names = {}
        
        for event in self.trace.events:

            if not event.name in self.event_count.keys():
                self.event_count[event.name] = 0

            method_name = method_names.get(event.name, None)
            
            if not method_name:
                method_name = "handle_%s" % event.name.replace(":", "_").replace("+", "_")
                method_names[event.name] = method_name
            
            # call the function to handle each event individually
            if hasattr(TraceParser, method_name):
                func = getattr(TraceParser, method_name)
                func(self, event)
        
        # print statistics after parsing the trace
        total = 0
        for e in self.event_count.keys():
            total += self.event_count[e]

        # filter leaks
        self.leaks = {}
        for pfn, page in self.pages.items():
            if not page["task"]["comm"].startswith("lttng-"):
                self.leaks[pfn] = page

        leak_locs = {}
        for pfn, page in self.leaks.items():
            page["callstack_kernel"] = self.kas.getforeach(page["callstack_kernel"])
            s = ":".join(page["callstack_kernel"])
            if s in leak_locs:
                leak_locs[s] += 1
            else:
                leak_locs[s] = 0
            pprint.pprint(page, self.log)
        self.log.write("Maybe leak summary:\n")
        for k in sorted(leak_locs, key=leak_locs.get, reverse=True):
            self.log.write("{} {}\n".format(leak_locs[k], k))
        
        self.log.write("Total event count: {}\n".format(total))
        self.log.write("Matches: {}\n".format(self.matches_count))
        self.log.write("Error alloc: {}\n".format(len(self.error_alloc)))
        self.log.write("Error free: {}\n".format(len(self.error_free)))
        self.log.write("Maybe leaks: {}\n".format(len(self.leaks)))

    def handle_irq_softirq_entry(self, event):
        cpu_id = event["cpu_id"]
        self.softirq[cpu_id] = True

    def handle_irq_softirq_exit(self, event):
        cpu_id = event["cpu_id"]
        self.softirq[cpu_id] = False

    def handle_sched_switch(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        prev_comm = event["prev_comm"]
        prev_tid = event["prev_tid"]
        prev_prio = event["prev_prio"]
        prev_state = event["prev_state"]
        next_comm = event["next_comm"]
        next_tid = event["next_tid"]
        next_prio = event["next_prio"]
        self.current[cpu_id] = { "tid": next_tid, "comm": next_comm }
        self.event_count[event.name] += 1
        
    def handle_kmem_mm_page_alloc(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        page = event["page"]
        pfn = event["pfn"]
        order = event["order"]
        gfp_flags = event["gfp_flags"]
        migratetype = event["migratetype"]

        csk = event.get("callstack_kernel", []) 

        entry = {
            "timestamp": timestamp,
            "cpu_id": cpu_id,
            "page": page,
            "pfn": pfn,
            "order": order,
            "gfp_flags": gfp_flags,
            "migratetype": migratetype,
            "callstack_kernel": csk,
        }
        entry["softirq"] = self.softirq.get(cpu_id, False)
        entry["task"] = self.current.get(cpu_id, {"tid": -1, "comm": ""})

        if pfn in self.pages:
            self.error_alloc.append(entry)
        else:
            self.pages[pfn] = entry
                
        self.event_count[event.name] += 1
    
    def handle_kmem_mm_page_free(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        page = event["page"]
        pfn = event["pfn"]
        order = event["order"]

        entry = {
            "timestamp": timestamp,
            "cpu_id": cpu_id,
            "page": page,
            "pfn": pfn,
            "order": order
        }
        entry["softirq"] = self.softirq.get(cpu_id, False)
        entry["task"] = self.current.get(cpu_id, {"tid": -1, "comm": ""})

        if pfn not in self.pages:
            self.error_free.append(entry)
        else:
            alloc = self.pages.pop(pfn)
            # drop the matches to avoid eating all the memory
            #self.matches.append({"alloc": alloc, "free": entry})
            self.matches_count += 1

        self.event_count[event.name] += 1

def process_trace(path):
    traces = TraceCollection()
    handle = traces.add_traces_recursive(path, "ctf")
    if handle is None:
        sys.exit(1)

    # try to find kallsyms file
    kalls = None
    for root, dirs, files in os.walk(path):
        for name in files:
            if name == "kallsyms":
                kalls = os.path.join(root, name)
    kas = Kallsyms()
    if kalls:
        with open(kalls, "r") as f:
            data = f.read()
            kas.load(data)
        print("using kallsyms file {} ({} symbols loaded)".format(kalls, len(kas.addr)))

    log_output = os.path.join(path, "memdebug.log")
    with open(log_output, "w") as log_file:
        t = TraceParser(traces, kas, log_file)
        t.parse()

    for h in handle.values():
        traces.remove_trace(h)

if __name__ == "__main__":
    import sys
    import os
    from lttnganalyses.core.kallsyms import Kallsyms
    parser = argparse.ArgumentParser(description='Trace parser')
    parser.add_argument('path', metavar="<path/to/trace>", help='Trace path')
    parser.add_argument('--foreach', default=False, action="store_true")
    args = parser.parse_args()

    print(args)
    paths = []
    if args.foreach:
        for item in os.listdir(args.path):
            p = os.path.join(args.path, item)
            if os.path.isdir(p):
                paths.append(p)
    else:
        paths.append(args.path)
    
    for path in paths:
        print("processing " + path)
        process_trace(path)
