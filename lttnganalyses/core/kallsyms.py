import bisect
import io
import re

class Kallsyms(object):
    EMPTY_ENTRY = { "name": "unkown", "addr": 0x0, "type": None }

    def __init__(self):
        self.syms = {}
        self.addr = []

    def __len__(self):
        return len(self.syms)
    
    def add(self, name, addr, stype):
        if addr in self.syms:
            #print("duplicate: {} and {} {} {}".format(self.syms[addr], name, hex(addr), stype))
            return
        bisect.insort(self.addr, addr)
        self.syms[addr] = { "name": name, "addr": addr, "type": stype }

    def get(self, addr):
        index = bisect.bisect(self.addr, addr)
        if index:
            loc = self.addr[index - 1]
            return self.syms[loc]
        return Kallsyms.EMPTY_ENTRY

    def getforeach(self, callstack):
        result = []
        for item in callstack:
            result.append(self.get(item)["name"])
        return result

    def load(self, data):
        #ffffffffa0009c56 r __param_str_floppy	[floppy]
        rx = re.compile("(?P<addr>[\w]+)\s+(?P<stype>\w+)\s+(?P<name>[a-zA-Z0-9_.]+)(\s+\[[a-z]+\])?\s*")
        buf = io.StringIO(data)
        n = 1
        while True:
            line = buf.readline()
            if line == '':
                break
            mx = rx.match(line)
            if not mx:
                raise ValueError("error parsing line {}".format(n))
            n += 1
            g = mx.groupdict()
            addr = int(g["addr"], 16)
            name = g["name"]
            stype = g["stype"]
            if stype == 't' or stype == 'T':
                self.add(name, addr, stype)

if __name__=="__main__":

    import sys

    data = """ffffffffa0009c56 r __param_str_floppy   [floppy]
ffffffffa0009c80 r floppy_pm_ops        [floppy]
ffffffffa000bac0 d __this_module        [floppy]
ffffffffa0007bfe t cleanup_module       [floppy]
ffffffffa0003f30 t floppy_interrupt     [floppy]
ffffffffa0009c20 r __mod_pnp_device_table       [floppy]
"""

    kas = Kallsyms()
    kas.load(data)
    assert(len(kas) == 2)

    for i in range(len(kas.addr) - 1):
        assert(kas.addr[i] < kas.addr[i+1])

    sym = kas.get(0xffffffffa0003f30 + 10)
    assert(sym["name"] == "floppy_interrupt")


