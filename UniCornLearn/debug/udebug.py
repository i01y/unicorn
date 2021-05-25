from enum import Enum
import capstone as cp

from unicorn import *
from constmap import *


class UCDebugMode(Enum):
    ALL = 0
    FAST = 1


class UCDebugDump:

    def __init__(self, uc: Uc, uc_arch, uc_mode):
        self.uc = uc
        self.arch = uc_arch
        self.mode = uc_mode

    def show_mem(self, addr, size):
        pass

    def show_asm(self, addr, size):
        pass

    def show_reg(self):
        pass


class UCDebugger:
    def __init__(self, uc: Uc, uc_arch, uc_mode, debug_mode: UCDebugMode = UCDebugMode.ALL):
        self.uc = uc
        self.arch = uc_arch
        self.mode = uc_mode
        self.bps = {}
        self.capstone = cp.Cs(UC_CP_ARCH[self.arch], UC_CP_MODE[self.mode])

    def dbg_mem(self, uc: Uc, access, address, length, value):
        pass

    def dbg_trace(self, uc: Uc, address, size):
        pass

    def add_bp(self, addr):
        self.enable_bp(addr)

    def enable_bp(self, addr, enable=True):
        self.bps[addr] = enable

    def del_bp(self, addr):
        if addr in self.bps.keys(): del self.bps[addr]

    def show_bp(self):
        for i in self.bps.items():
            print(f"{hex(i[0])}: {i[1]}")
