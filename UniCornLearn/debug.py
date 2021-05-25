import capstone as cp
from unicorn import *
from constmap import *
from util.base import *

BPT_EXECUTE = 1
BPT_MEMREAD = 2
UDBG_MODE_ALL = 1
UDBG_MODE_FAST = 2


def _dbg_trace(uc: Uc, address, size, self):
    self.tracks.append(address)


def _dbg_memory(uc: Uc, access, address, length, value, self):
    pass


def _dbg_trace_internal(uc: Uc, address, size, self):
    pass


class UnicornDebugger:
    def __init__(self, uc: Uc, mode=UDBG_MODE_ALL):
        self.tracks = []
        self.uc = uc
        self.arch = uc._arch
        self.mode = uc._mode
        self.bps = []
        self.tmp_bp = 0
        self.error = ''
        self.last_cmd = ''
        self.dis_count = 5
        self.step = False
        self.sym_handler = hex
        self._capstone_arm = None
        self._capstone_thumb = None

        if self.arch != UC_ARCH_ARM:
            uc.emu_stop()
            raise RuntimeError("arch:%d is not supported! " % self.arch)

        capstone_arch = UC_CP_ARCH[self.arch]
        capstone_mode = UC_CP_MODE[self.mode]

        self._capstone_thumb = cp.Cs(cp.CS_ARCH_ARM, cp.CS_MODE_THUMB)
        self._capstone_arm = cp.Cs(cp.CS_ARCH_ARM, cp.CS_MODE_ARM)
        self._capstone = self._capstone_thumb

        if mode == UDBG_MODE_ALL:
            uc.hook_add(UC_HOOK_CODE, _dbg_trace, self)

        uc.hook_add(UC_HOOK_MEM_UNMAPPED, _dbg_memory, self)
        uc.hook_add(UC_HOOK_MEM_FETCH_PROT, _dbg_memory, self)

        self.reg_table = REG_TABLE[self.arch]
        self.reg_table_re = reverse_dict(self.reg_table)

    def dump_mem(self, addr, size):
        data = self.uc.mem_read(addr, size)
        dump_hex(data, addr)

    def dump_asm(self, addr, size):
        md = self._capstone
        data = self.uc.mem_read(addr, size)
        content = [f"{self.sym_handler(ins.address)}:\t{ins.mnemonic}\t{ins.op_str}" for ins in md.disasm(data, addr)]
        print(''.join(content))

    def dump_reg(self):
        result_format = ''
        count = 0
        values = [f"{self.reg_table[rid]} = {self.uc.reg_read(rid)}" for rid in self.reg_table]

        for value in values:
            result_format += f" {value}" if count != 0 and 0 != (count % 4) else f"{value}\n"
            count += 1
        print(result_format)

    def write_reg(self, reg_name, value):
        rid = self.reg_table_re.get(reg_name)
        if rid is None:
            print(f"[Debugger Error] Reg not found:{reg_name}")
            return
        self.uc.reg_write(rid, value)

    def set_symbol_name_handler(self, handler):
        self.sym_handler = handler

    def list_bpt(self):
        for idx in range(len(self.bps)):
            print("[%d] %s" % (idx, self.sym_handler(self.bps[idx])))

    def add_bpt(self, addr):
        self.bps.append(addr)

    def del_bpt(self, addr):
        self.bps.remove(addr)

    def show_help(self):
        help_info = """
        # commands
        # set reg <regname> <value>
        # set bpt <addr>
        # n[ext]
        # s[etp]
        # r[un]
        # dump <addr> <size>
        # list bpt
        # del bpt <addr>
        # stop
        # a/t change arm/thumb
        # f show ins flow
        """
        print(help_info)
