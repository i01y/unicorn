from unicorn import *
from unicorn.arm_const import *

ADDRESS = 0x10000
ARM_CODE = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0"  # mov r0, #0x37 sub r1, r2, r3


def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))


if __name__ == '__main__':
    try:
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)  # Uc对象代表一个独立的虚拟机实例,它有独立的寄存器和内存等资源
        mu.mem_map(ADDRESS, 2 * 0x10000)  # 映射内存
        mu.mem_write(ADDRESS, ARM_CODE)  # 写入内存
        mu.reg_write(UC_ARM_REG_R0, 0x1)  # 给寄存器赋值
        mu.reg_write(UC_ARM_REG_R2, 0x20)
        mu.reg_write(UC_ARM_REG_R3, 0x3)
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS)  # 添加指令级Hook
        mu.emu_start(ADDRESS, ADDRESS + len(ARM_CODE))
        r0 = mu.reg_read(UC_ARM_REG_R0)
        r1 = mu.reg_read(UC_ARM_REG_R1)
        print(f"R0: {r0}")
        print(f"R1: {r1}")
    except UcError as e:
        print(f"ERROR: {e}")
