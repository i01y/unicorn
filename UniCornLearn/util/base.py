from colorama import Fore
from pyhexdump import hexdump

def hex_list(m):
    return " ".join([f"{v:02X}" for v in m])


def recover(a):
    """
    Convert the bytearray back into a string. However, modify the string so only
    ascii printable characters are there.
    """
    b = []
    for c in a:
        if 0x7e >= c >= 0x20:  # only print ascii chars
            b.append(chr(c))
        else:  # all others just replace with '.'
            b.append(Fore.RED + '.' + Fore.GREEN)
    ret = ''.join(b)
    return ret


def dump_hex(data, base=0, cols=80):
    content = [f"{Fore.MAGENTA}dump: {len(data)} bytes",
               f'{Fore.MAGENTA}ascii characters: {Fore.GREEN}GREEN{Fore.MAGENTA} non-ascii: {Fore.RED}RED',
               f"{Fore.BLUE}{'Offset(h)':>6} | {hex_list(range(16))} | {'String'}",
               f"{'-' * cols}{Fore.RESET}"
               ]
    print_string = Fore.BLUE + '{:09X} | ' + Fore.RESET + '{} ' + Fore.GREEN + '| {}' + Fore.RESET
    size = 16
    buff = []
    line = [0]*size
    for i, char in enumerate(data):
        if i % size == 0 and i != 0:
            buff.append(line)
            line = [0]*size
            line[0] = char
        else:
            line[i % size] = char

            if i == len(data) - 1:
                buff.append(line)
    for i, line in enumerate(buff):
        content.append(print_string.format(i * size + base, hex_list(line), recover(line)))

    print('\n'.join(content))
