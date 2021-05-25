import capstone
from unicorn import *


def reverse_dict(m: dict) -> dict:
    return {v: k for k, v in m.items()}


REG_ARM = {arm_const.UC_ARM_REG_R0: "R0",
           arm_const.UC_ARM_REG_R1: "R1",
           arm_const.UC_ARM_REG_R2: "R2",
           arm_const.UC_ARM_REG_R3: "R3",
           arm_const.UC_ARM_REG_R4: "R4",
           arm_const.UC_ARM_REG_R5: "R5",
           arm_const.UC_ARM_REG_R6: "R6",
           arm_const.UC_ARM_REG_R7: "R7",
           arm_const.UC_ARM_REG_R8: "R8",
           arm_const.UC_ARM_REG_R9: "R9",
           arm_const.UC_ARM_REG_R10: "R10",
           arm_const.UC_ARM_REG_R11: "R11",
           arm_const.UC_ARM_REG_R12: "R12",
           arm_const.UC_ARM_REG_R13: "R13",
           arm_const.UC_ARM_REG_R14: "R14",
           arm_const.UC_ARM_REG_R15: "R15",
           arm_const.UC_ARM_REG_PC: "PC",
           arm_const.UC_ARM_REG_SP: "SP",
           arm_const.UC_ARM_REG_LR: "LR"
           }

REG_TABLE = {UC_ARCH_ARM: REG_ARM}
UC_CP_ARCH = {
    UC_ARCH_ARM: capstone.CS_ARCH_ARM,
    UC_ARCH_ARM64: capstone.CS_ARCH_ARM64,
    UC_ARCH_MIPS: capstone.CS_ARCH_MIPS,
    UC_ARCH_X86: capstone.CS_ARCH_X86,
    UC_ARCH_PPC: capstone.CS_ARCH_PPC,
    UC_ARCH_SPARC: capstone.CS_ARCH_SPARC,
    UC_ARCH_M68K: capstone.CS_ARCH_M68K,
    UC_ARCH_MAX: capstone.CS_ARCH_MAX
}

UC_CP_MODE = {
    UC_MODE_ARM: capstone.CS_MODE_ARM,
    UC_MODE_THUMB: capstone.CS_MODE_THUMB,
    UC_MODE_MCLASS: capstone.CS_MODE_MCLASS,
    UC_MODE_V8: capstone.CS_MODE_V8,
    UC_MODE_MICRO: capstone.CS_MODE_MICRO,
    UC_MODE_MIPS3: capstone.CS_MODE_MIPS3,
    UC_MODE_MIPS32R6: capstone.CS_MODE_MIPS32R6,
    UC_MODE_MIPS32: capstone.CS_MODE_MIPS32,
    UC_MODE_MIPS64: capstone.CS_MODE_MIPS64,
    UC_MODE_16: capstone.CS_MODE_16,
    UC_MODE_32: capstone.CS_MODE_32,
    UC_MODE_64: capstone.CS_MODE_64,
    UC_MODE_QPX: capstone.CS_MODE_QPX,
    UC_MODE_V9: capstone.CS_MODE_V9
}
