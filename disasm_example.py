#!/usr/bin/env python3
######################################################################
#
# Be sure to use python3...
#
# This is just an example to get you started if you are having
# difficulty starting the assignment. It is by no means the most
# efficient way to implement this disassembler, however, it is one
# that can easily be followed and extended to complete the requirements
#
# You may want to import other modules, but certainly not required
# This implements linear sweep..this can be modified to implement
# recursive descent as well
#
######################################################################

GLOBAL_REGISTER_NAMES = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

# Key is the opcode - value is a list of useful information
GLOBAL_OPCODE_MAP = {

    # duplicates
    0x81: ['tbd', True, 'mi'],     # GLOBAL_81_INDEXES
    # 0x81: ['add ', True, 'mi'],   # /0
    # 0x81: ['or  ', True, 'mi'],   # /1
    # 0x81: ['and ', True, 'mi'],   # /4
    # 0x81: ['sub ', True, 'mi'],   # /5
    # 0x81: ['xor ', True, 'mi'],   # /6
    # 0x81: ['cmp ', True, 'mi'],   # /7

    0xFF: ['tbd', True, 'm'],      # GLOBAL_FF_INDEXES
    # 0xFF: ['inc  ', True, 'm'],    # /0
    # 0xFF: ['dec  ', True, 'm'],    # /1
    # 0xFF: ['call ', True, 'm'],    # /2       Call near, absolute indirect, address given in r/m32.
    # 0xFF: ['jmp  ', True, 'm'],    # /4       Jump near, absolute indirect, address given in r/m32.
    # 0xFF: ['push ', True, 'm'],    # /6

    0xF7: ['tbd', True, 'm'],      # GLOBAL_F7_INDEXES
    # 0xF7: ['test   ', True, 'mi'],  # /0
    # 0xF7: ['not    ', True, 'm'],   # /2
    # 0xF7: ['idiv   ', True, 'm'],   # /7

    0x0F: ['tbd', False, 'd', 4],
    # 0x0F: ['jz      ', False, 'd', 4],        # jz rel32          # /84
    # 0x0F: ['jnz     ', False, 'd', 4],        # jnz rel32         # /85
    # 0x0F: ['nop     ', True, 'm'],                                #
    # 0x0F: ['clflush ', True, 'm'],                                #

    # nop
    0x90: ['nop     ', False, 'zo'],
    # see duplicates

    # clflush
    # see duplicates

    # not
    # see duplicates

    # idiv
    # see duplicates

    # add
    0x05: ['add     ', False, 'id', 4],
    0x01: ['add     ', True, 'mr'],
    0x03: ['add     ', True, 'rm'],

    # sub
    0x2D: ['sub     ', False, 'id', 4],
    0x09: ['sub     ', True, 'mr'],
    0x0B: ['sub     ', True, 'rm'],

    # or
    0x0D: ['or      ', False, 'id', 4],
    0x29: ['or      ', True, 'mr'],
    0x2B: ['or      ', True, 'rm'],

    # xor
    0x35: ['xor     ', False, 'id', 4],         # DOUBLE CHECK
    0x31: ['xor     ', True, 'mr'],
    0x33: ['xor     ', True, 'rm'],

    # and
    0x25: ['and     ', False, 'id', 4],
    0x21: ['and     ', True, 'mr'],
    0x23: ['and     ', True, 'rm'],

    # ret
    0xC3: ['retn    ', False, 'zo'],
    0xCB: ['retf    ', False, 'zo'],
    0xC2: ['retn    ', False, 'id', 2],
    0xCA: ['retf    ', False, 'id', 2],

    # jz/jnz
    0x74: ['jz      ', False, 'd', 1],          # jz rel8
    0x75: ['jnz     ', False, 'd', 1],          # jnz rel8

    # jmp
    0xEB: ['jmp     ', False, 'd', 1],             # jmp rel8
    0xE9: ['jmp     ', False, 'd', 4],             # jmp rel32

    # call
    0xE8: ['call    ', False, 'd', 4],

    # pop
    # 58+rd pop r32, False, 'o'
    0x58: ['pop     ', False, 'o', 0x58],
    0x59: ['pop     ', False, 'o', 0x58],
    0x5A: ['pop     ', False, 'o', 0x58],
    0x5B: ['pop     ', False, 'o', 0x58],
    0x5C: ['pop     ', False, 'o', 0x58],
    0x5D: ['pop     ', False, 'o', 0x58],
    0x5E: ['pop     ', False, 'o', 0x58],
    0x5F: ['pop     ', False, 'o', 0x58],
    0x8F: ['pop     ', True, 'm'],     # /0

    # push
    0x68: ['push    ', False, 'id', 4],
    # 50+rd push r32, False, 'o'
    0x57: ['push    ', False, 'o', 0x50],
    0x56: ['push    ', False, 'o', 0x50],
    0x55: ['push    ', False, 'o', 0x50],
    0x54: ['push    ', False, 'o', 0x50],
    0x53: ['push    ', False, 'o', 0x50],
    0x52: ['push    ', False, 'o', 0x50],
    0x51: ['push    ', False, 'o', 0x50],
    0x50: ['push    ', False, 'o', 0x50],

    # dec
    # 0x48 + rd: ['dec    ', False, 'o'],
    0x48: ['dec     ', False, 'o', 0x48],
    0x49: ['dec     ', False, 'o', 0x48],
    0x4A: ['dec     ', False, 'o', 0x48],
    0x4B: ['dec     ', False, 'o', 0x48],
    0x4C: ['dec     ', False, 'o', 0x48],
    0x4D: ['dec     ', False, 'o', 0x48],
    0x4E: ['dec     ', False, 'o', 0x48],
    0x4F: ['dec     ', False, 'o', 0x48],

    # inc
    # 0x40 + rd: ['inc    ', False, 'o'],
    0x40: ['inc     ', False, 'o', 0x40],
    0x41: ['inc     ', False, 'o', 0x40],
    0x42: ['inc     ', False, 'o', 0x40],
    0x43: ['inc     ', False, 'o', 0x40],
    0x44: ['inc     ', False, 'o', 0x40],
    0x45: ['inc     ', False, 'o', 0x40],
    0x46: ['inc     ', False, 'o', 0x40],
    0x47: ['inc     ', False, 'o', 0x40],

    # cmp
    0x3D: ['cmp     ', False, 'id', 4],
    0x39: ['cmp     ', True, 'mr'],
    0x3B: ['cmp     ', True, 'rm'],

    # test
    0xA9: ['test    ', False, 'id', 4],
    0x85: ['test    ', True, 'mr'],

    # lea
    0x8D: ['lea     ', True, 'rm'],

    # mov
    0x89: ['mov     ', True, 'mr'],
    0x8B: ['mov     ', True, 'rm'],
    0xC7: ['mov     ', True, 'mi'],
    # 0xB8 + rd: ['mov ', False, 'oi'],
    0xB8: ['mov     ', False, 'oi', 0xB8],
    0xB9: ['mov     ', False, 'oi', 0xB8],
    0xBA: ['mov     ', False, 'oi', 0xB8],
    0xBB: ['mov     ', False, 'oi', 0xB8],
    0xBC: ['mov     ', False, 'oi', 0xB8],
    0xBD: ['mov     ', False, 'oi', 0xB8],
    0xBE: ['mov     ', False, 'oi', 0xB8],
    0xBF: ['mov     ', False, 'oi', 0xB8],

    # movsd
    0xA5: ['movsd   ', False, 'zo'],

    # repne cmpsd repeat not equal
    0xF2: ['repne cmpsd  ', False, 'zo'],   # 0xA7

}

# Duplicate Opcodes
GLOBAL_81_INDEXES = ['add     ', 'or      ', '', '', 'and     ', 'sub     ', 'xor     ', 'cmp     ']
GLOBAL_FF_INDEXES = ['inc     ', 'dec     ', 'call    ', '', 'jmp     ', '', 'push    ', '']
GLOBAL_F7_INDEXES = ['test    ', '', 'not     ', '', '', '', '', 'idiv    ']

def isValidOpcode(opcode):
    if opcode in GLOBAL_OPCODE_MAP.keys():
        return True
    return False

def parseMODRM(modrm):
    # mod = (modrm & 0xC0) >> 6
    # reg = (modrm & 0x38) >> 3
    # rm  = (modrm & 0x07)

    mod = (modrm & 0b11000000) >> 6
    reg = (modrm & 0b00111000) >> 3
    rm = (modrm & 0b00000111)
    return mod, reg, rm

def saveToFile(output, labelList):
    f = open("output.txt", "a")
    for addr in sorted(output):
        for label in sorted(labelList):
            if label < addr:
                f.write('---' + '%s: %s' % (label, labelList[label]) + '\n')
                labelList.pop(label)
            else:
                break
        f.write('%s: %s' % (addr, output[addr]) + '\n')
    for addr in sorted(labelList):
        f.write('---' + '%s: %s' % (addr, labelList[addr]) + '\n')
    f.close()

def writeLineFile(output):
    f = open("output.txt", "a")
    f.write(output + '\n')
    f.close()

def printDisassm(output, labelList):

    # Good idea to add a "global label" structure...
    # TODO can check to see if "addr" is in it for a branch reference

    for addr in sorted(output):
        if addr in labelList:
            print('%s: %s' % (addr, labelList[addr]))
        print('%s: %s' % (addr, output[addr]))

# TAKEN FROM INTERNET
def twos_complement(hexstr, bits):
    value = int(hexstr, 16)
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value

# TAKEN FROM INTERNET
def sign_extend(value: int, bits: int) -> int:
    """ Perform sign extension operation.
    """
    sign_bit = 1 << (bits - 1)
    mask = sign_bit - 1
    return (value & mask) - (value & sign_bit)

def disassemble(b):

    # manage final output key is address
    outputList = {}
    labelList = {}
    outputPrint = ''
    i = 0

    while i < len(b):
        implemented = False
        opcode = b[i]	                        # current byte to work on
        instruction_bytes = "%02X" % b[i]       # making b[i] int and converting to 2hex
        instruction = ''
        orig_index = i
        i += 1                                  # weve consumed the OPCODE byte

        # Hint this is here for a reason, but is this the only spot
        # such a check is required in?
        if i > len(b):
           break

        if isValidOpcode(opcode):
            outputPrint += '\nIndex -> %d' % i + ' 0x' + '%02x' % (i-1) + '\n'
            outputPrint += 'Found valid opcode ' + instruction_bytes + ' ' + GLOBAL_OPCODE_MAP[opcode][0] + '\n'
            outputPrint += 'opcode[2] ' + GLOBAL_OPCODE_MAP[opcode][2] + '\n'

            if i + 10 < len(b):
                t = i - 1
                for y in range(8):
                    outputPrint += "%02X" % b[t+y] + ', '
                outputPrint += '\n'

            if 1:                                       # TRUE # TODO Check size
                li = GLOBAL_OPCODE_MAP[opcode]

                if opcode == 0x0F:
                    # 0x0F: ['jz      ', False, 'd', 4],        # jz rel32          # /84
                    # 0x0F: ['jnz     ', False, 'd', 4],        # jnz rel32         # /85
                    # 0x0F: ['nop     ', True, 'm'],                                # /1F 0
                    # 0x0F: ['clflush ', True, 'm'],                                # /AE 7
                    signal = b[i]
                    instruction_bytes += ' ' + "%02X" % b[i]
                    i += 1
                    if signal == 0x84:
                        li[0] = 'jz      '
                        li[1] = False
                        li[2] = 'd'
                    elif signal == 0x85:
                        li[0] = 'jnz     '
                        li[1] = False
                        li[2] = 'd'
                    elif signal == 0x1F:
                        li[0] = 'nop     '
                        li[1] = True
                        li[2] = 'm'
                    elif signal == 0xAE:
                        li[0] = 'clflush '
                        li[1] = True
                        li[2] = 'm'

                if li[1]:
                    outputPrint += 'REQUIRES MODRM BYTE' + '\n'

                    mod, reg, rm = parseMODRM(b[i])
                    outputPrint += 'mod ' + str(mod) + '\n'
                    outputPrint += 'reg ' + str(reg) + '\n'
                    outputPrint += 'rm ' + str(rm) + '\n'

                    if li[0] != 'tbd':
                        instruction += li[0]
                    else:
                        if instruction_bytes == '81':
                            instruction += GLOBAL_81_INDEXES[reg]
                        elif instruction_bytes == 'FF':
                            instruction += GLOBAL_FF_INDEXES[reg]
                        elif instruction_bytes == 'F7':
                            instruction += GLOBAL_F7_INDEXES[reg]
                            # TODO CLEAN UP??
                            if GLOBAL_F7_INDEXES[reg] == 'test    ':
                                li[2] = 'mi'

                    instruction_bytes += ' ' + "%02X" % b[i]
                    i += 1      # we've consumed MODRM now

                    if mod == 3:
                        outputPrint += 'r/m32 operand is direct register' + '\n'

                        if li[2] == 'mr':
                            outputPrint += 'mr' + '\n'
                            implemented = True
                            instruction += GLOBAL_REGISTER_NAMES[rm]
                            instruction += ', '
                            instruction += GLOBAL_REGISTER_NAMES[reg]
                            # instruction += '    Q: 008'

                        elif li[2] == 'rm':
                            # outputPrint += 'rm' + '\n'
                            # implemented = True
                            # instruction += GLOBAL_REGISTER_NAMES[reg]
                            # instruction += ', '
                            # instruction += GLOBAL_REGISTER_NAMES[rm]
                            # instruction += '    Q: 009'
                            outputPrint += 'Implement\n'

                        elif li[2] == 'mi':
                            outputPrint += 'mi' + '\n'
                            implemented = True
                            disp = ''
                            for y in range(4):
                                disp += "%02X" % b[i]
                                instruction_bytes += ' ' + "%02X" % b[i]
                                i += 1
                            instruction += GLOBAL_REGISTER_NAMES[rm] + ', 0x'
                            disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                            instruction += disp
                            # instruction += '    Q: 002 - VALID'

                        elif li[2] == 'm':
                            outputPrint += 'm' + '\n'
                            implemented = True
                            instruction += GLOBAL_REGISTER_NAMES[rm]
                            # instruction += '    Q: 005'

                        else:
                            outputPrint += 'Implement\n'

                    elif rm == 4:         # R/M bits = 100
                        outputPrint += 'SIB required.\n'

                        instruction_bytes += ' ' + "%02X" % b[i]
                        scale, index, base = parseMODRM(b[i])
                        i += 1

                        outputPrint += 'scale ' + str(scale) + '\n'
                        outputPrint += 'index ' + str(index) + '\n'
                        outputPrint += 'base ' + str(base) + '\n'

                        if index == 4:
                            outputPrint += 'NO SCALE.\n'

                            # 2 - 0 - 4
                            if mod == 2:
                                # 'r/m32 operand is [ reg * mult + disp32 ]

                                if li[2] == 'rm':
                                    implemented = True
                                    instruction += GLOBAL_REGISTER_NAMES[reg] + ', [' + GLOBAL_REGISTER_NAMES[index]
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                    instruction += ' + 0x' + disp + ']'
                                    # instruction += '    Q: 010'
                                    # outputPrint += 'Implement\n'

                                elif li[2] == 'mr':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                    instruction += disp + '], '
                                    instruction += GLOBAL_REGISTER_NAMES[reg]
                                    # instruction += '    Q: 011'
                                    # outputPrint += 'Implement\n'

                                elif li[2] == 'mi':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                    instruction += disp + ']'
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                    instruction += ', 0x' + disp
                                    # outputPrint += 'Implement\n'
                                    # instruction += '    Q: 012'

                                elif li[2] == 'm':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[index] + ' + 0x'
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                    instruction += disp + ']'
                                    # outputPrint += 'Implement\n'
                                    # instruction += '    Q: 013'

                            elif mod == 1:
                                # 'r/m32 operand is [ reg * mult + disp8 ]

                                if li[2] == 'rm':
                                    implemented = True
                                    instruction += GLOBAL_REGISTER_NAMES[reg] + ', [' + GLOBAL_REGISTER_NAMES[index]
                                    instruction += ' + 0x' + "%02X" % b[i] + ']'
                                    instruction_bytes += ' ' + "%02X" % b[i]
                                    i += 1
                                    # instruction += '    Q: 014'

                                elif li[2] == 'mr':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                    instruction += "%02X" % b[i] + '], '
                                    instruction_bytes += ' ' + "%02X" % b[i]
                                    i += 1
                                    instruction += GLOBAL_REGISTER_NAMES[reg]
                                    # outputPrint += 'Implement\n'
                                    # instruction += '    Q: 015'

                                elif li[2] == 'mi':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                    instruction += "%02X" % b[i] + '], '
                                    instruction_bytes += ' ' + "%02X" % b[i]
                                    i += 1
                                    size = 4
                                    disp = ''
                                    for y in range(size):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                    instruction += '0x' + disp
                                    # instruction += '    Q: 016'

                                elif li[2] == 'm':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[index] + ' + 0x' + "%02X" % b[i] + ']'
                                    i += 1
                                    # instruction += '    Q: 017'

                            elif mod == 0:

                                if li[2] == 'rm':
                                    implemented = True
                                    instruction += GLOBAL_REGISTER_NAMES[reg] + ', '
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ']'
                                    # instruction += '    Q: 018'

                                elif li[2] == 'mr':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + '], '
                                    instruction += GLOBAL_REGISTER_NAMES[reg]
                                    # instruction += '    Q: 019'

                                elif li[2] == 'mi':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[rm]
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                    instruction += '], 0x' + disp
                                    # instruction += '    Q: 020'

                                elif li[2] == 'm':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[index] + ' * ' + str(pow(2, scale)) + ']'
                                    # instruction += '    Q: 021'

                        else:
                            outputPrint += 'SCALE.\n'
                            # 2 - 0 - 4
                            if mod == 2:
                                # 'r/m32 operand is [ reg * mult + disp32 ]

                                if li[2] == 'rm':
                                    implemented = True
                                    instruction += GLOBAL_REGISTER_NAMES[reg] + ', ['
                                    instruction += GLOBAL_REGISTER_NAMES[base] + ' + '
                                    instruction += GLOBAL_REGISTER_NAMES[index] + ' * ' + str(pow(2, scale))
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                    instruction += ' + 0x' + disp + ']'
                                    # instruction += '    Q: 022'
                                    # outputPrint += 'Implement\n'

                                elif li[2] == 'mr':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[base] + ' + ' + GLOBAL_REGISTER_NAMES[index] + ' * ' + str(pow(2, scale)) + ' + 0x'
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                    instruction += disp + '], '
                                    instruction += GLOBAL_REGISTER_NAMES[reg]
                                    # instruction += '    Q: 023'

                                elif li[2] == 'mi':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[base] + ' + ' + GLOBAL_REGISTER_NAMES[index] + ' * ' + str(pow(2, scale)) + ' + 0x'
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                    instruction += disp + ']'
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                    instruction += ', 0x' + disp
                                    # instruction += '    Q: 024'

                                elif li[2] == 'm':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[base] + ' + ' + GLOBAL_REGISTER_NAMES[index] + ' * ' + str(pow(2, scale)) + ' + 0x'
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                    instruction += disp + ']'
                                    # instruction += '    Q: 025'

                            elif mod == 1:
                                # 'r/m32 operand is [ reg * mult + disp8 ]

                                if li[2] == 'rm':
                                    implemented = True
                                    instruction += GLOBAL_REGISTER_NAMES[reg] + ', ['
                                    instruction += GLOBAL_REGISTER_NAMES[base] + ' + '
                                    instruction += GLOBAL_REGISTER_NAMES[index] + ' * ' + str(pow(2, scale))
                                    instruction += ' + 0x' + "%02X" % b[i] + ']'
                                    instruction_bytes += ' ' + "%02X" % b[i]
                                    i += 1
                                    # instruction += '    Q: 026'

                                elif li[2] == 'mr':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[base] + ' + '
                                    instruction += GLOBAL_REGISTER_NAMES[index] + ' * ' + str(pow(2, scale)) + ' + 0x'
                                    instruction += "%02X" % b[i] + '], '
                                    instruction_bytes += ' ' + "%02X" % b[i]
                                    i += 1
                                    instruction += GLOBAL_REGISTER_NAMES[reg]
                                    # instruction += '    Q: 027'

                                elif li[2] == 'mi':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[base] + ' + '
                                    instruction += GLOBAL_REGISTER_NAMES[index] + ' * ' + str(pow(2, scale)) + ' + 0x'
                                    instruction += "%02X" % b[i] + '], '
                                    instruction_bytes += ' ' + "%02X" % b[i]
                                    i += 1
                                    size = 4
                                    disp = ''
                                    for y in range(size):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                    instruction += '0x' + disp
                                    # instruction += '    Q: 028'

                                elif li[2] == 'm':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[base] + ' + '
                                    instruction += GLOBAL_REGISTER_NAMES[index] + ' * ' + str(pow(2, scale)) + ' + 0x'
                                    instruction += "%02X" % b[i] + ']'
                                    i += 1
                                    # instruction += '    Q: 029'

                            elif mod == 0:

                                if li[2] == 'rm':
                                    implemented = True
                                    instruction += GLOBAL_REGISTER_NAMES[reg] + ', '
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[index] + ' * ' + str(pow(2, scale)) + ']'
                                    # instruction += '    Q: 030'

                                elif li[2] == 'mr':
                                    implemented = True
                                    if scale == 0:
                                        instruction += '[' + GLOBAL_REGISTER_NAMES[index] + ' * 2' + '], '
                                        instruction += GLOBAL_REGISTER_NAMES[reg]
                                    else:
                                        instruction += '[' + GLOBAL_REGISTER_NAMES[index] + ' * ' + str(pow(2, scale))
                                        disp = ''
                                        for y in range(4):
                                            disp += "%02X" % b[i]
                                            instruction_bytes += ' ' + "%02X" % b[i]
                                            i += 1
                                        disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                        instruction += ' + 0x' + disp + '], '
                                        instruction += GLOBAL_REGISTER_NAMES[reg]
                                    # instruction += '    Q: 031'

                                elif li[2] == 'mi':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[index] + ' * ' + str(pow(2, scale))
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                    instruction += ' + 0x' + disp + ']'
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                    instruction += ', 0x' + disp
                                    # instruction += '    Q: 032'

                                elif li[2] == 'm':
                                    implemented = True
                                    if scale == 0:
                                        instruction += '[' + GLOBAL_REGISTER_NAMES[index] + ' * 2' + ']'
                                    else:
                                        instruction += '[' + GLOBAL_REGISTER_NAMES[index] + ' * ' + str(pow(2, scale)) + ']'
                                        disp = ''
                                        for y in range(4):
                                            disp += "%02X" % b[i]
                                            instruction_bytes += ' ' + "%02X" % b[i]
                                            i += 1
                                        disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                        instruction += ', 0x' + disp
                                    # instruction += '    Q: 033'

                    # MOD 0 - 2 SWITCH
                    else:
                        outputPrint += 'SIB NOT required.\n'

                        if mod == 2:
                            # 'r/m32 operand is [ reg + disp32 ]

                            if li[2] == 'mr':
                                implemented = True
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                disp = ''
                                for y in range(4):
                                    disp += "%02X" % b[i]
                                    instruction_bytes += ' ' + "%02X" % b[i]
                                    i += 1

                                disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)])) + '], '
                                instruction += disp + GLOBAL_REGISTER_NAMES[reg]
                                # instruction += '    Q: 034'

                            elif li[2] == 'rm':
                                implemented = True
                                instruction += GLOBAL_REGISTER_NAMES[reg] + ', ['
                                instruction += GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                disp = ''
                                for y in range(4):
                                    disp += "%02X" % b[i]
                                    instruction_bytes += ' ' + "%02X" % b[i]
                                    i += 1
                                disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                instruction += disp + ']'
                                # instruction += '    Q: 035'

                            elif li[2] == 'mi':
                                implemented = True
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                disp = ''
                                for y in range(4):
                                    disp += "%02X" % b[i]
                                    instruction_bytes += ' ' + "%02X" % b[i]
                                    i += 1
                                disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                instruction += disp + ']'
                                disp = ''
                                for y in range(4):
                                    disp += "%02X" % b[i]
                                    instruction_bytes += ' ' + "%02X" % b[i]
                                    i += 1
                                disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                instruction += ', 0x' + disp
                                # instruction += '    Q: 007'

                            elif li[2] == 'm':
                                implemented = True
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                disp = ''
                                for y in range(4):
                                    disp += "%02X" % b[i]
                                    instruction_bytes += ' ' + "%02X" % b[i]
                                    i += 1
                                disp = ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                instruction += disp + ']'
                                # instruction += '    Q: 036'

                        elif mod == 1:
                            # 'r/m32 operand is [ reg + disp8 ]

                            if li[2] == 'mr':
                                implemented = True
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                instruction += "%02X" % b[i] + '], '
                                instruction_bytes += ' ' + "%02X" % b[i]
                                i += 1
                                instruction += GLOBAL_REGISTER_NAMES[reg]
                                # instruction += '    Q: 037'

                            elif li[2] == 'rm':
                                implemented = True
                                instruction += GLOBAL_REGISTER_NAMES[reg]
                                instruction += ', [' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                instruction += "%02X" % b[i] + ']'
                                instruction_bytes += ' ' + "%02X" % b[i]
                                i += 1
                                # instruction += '    Q: 038'

                            elif li[2] == 'mi':
                                implemented = True
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                instruction += "%02X" % b[i] + '], '
                                instruction_bytes += ' ' + "%02X" % b[i]
                                i += 1
                                size = 4
                                disp = ''
                                for y in range(size):
                                    disp += "%02X" % b[i]
                                    instruction_bytes += ' ' + "%02X" % b[i]
                                    i += 1
                                instruction += '0x' + ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))
                                # instruction += '    Q: 006'

                            elif li[2] == 'm':
                                implemented = True
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x' + "%02X" % b[i] + ']'
                                instruction_bytes += ' ' + "%02X" % b[i]
                                i += 1
                                # instruction += '    Q: 039'

                        elif mod == 0:

                            #  Mod 0 Special case SWITCH
                            if rm == 5:         # R/M bits = 101
                                # 'r/m32 operand is [disp32]
                                outputPrint += 'rm ' + str(rm) + ' therefore, special case\n'

                                if li[2] == 'mr':
                                    implemented = True
                                    instruction += '[0x'
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    instruction += ''.join(reversed([disp[i:i+2] for i in range(0, len(disp), 2)]))
                                    instruction += '], ' + GLOBAL_REGISTER_NAMES[reg]
                                    # instruction += '    Q: 040'

                                elif li[2] == 'rm':
                                    implemented = True
                                    instruction += GLOBAL_REGISTER_NAMES[reg]
                                    instruction += ', [0x'
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    instruction += ''.join(reversed([disp[i:i+2] for i in range(0, len(disp), 2)])) + ']'
                                    # instruction += '    Q: 041'

                                elif li[2] == 'mi':
                                    implemented = True
                                    instruction += '[0x'
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    instruction += ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)])) + ']'
                                    instruction += ', 0x'
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    instruction += ''.join(reversed([disp[i:i+2] for i in range(0, len(disp), 2)]))
                                    # instruction += '    Q: 004 - VALID'

                                elif li[2] == 'm':
                                    implemented = True
                                    instruction += '[0x'
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    instruction += ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)])) + ']'
                                    # instruction += '    Q: 042'

                            else:
                                outputPrint += 'NOT special case\n'
                                # 'r/m32 operand is [reg]

                                if li[2] == 'rm':
                                    implemented = True
                                    instruction += GLOBAL_REGISTER_NAMES[reg]
                                    instruction += ', [' + GLOBAL_REGISTER_NAMES[rm] + ']'
                                    # instruction += '    Q: 043'

                                elif li[2] == 'mr':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + '], '
                                    instruction += GLOBAL_REGISTER_NAMES[reg]
                                    # instruction += '    Q: 044'

                                elif li[2] == 'mi':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ']'
                                    disp = ''
                                    for y in range(4):
                                        disp += "%02X" % b[i]
                                        instruction_bytes += ' ' + "%02X" % b[i]
                                        i += 1
                                    instruction += ', 0x' + ''.join(reversed([disp[i:i+2] for i in range(0, len(disp), 2)]))
                                    # instruction += '    Q: 001'

                                elif li[2] == 'm':
                                    implemented = True
                                    instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ']'
                                    # instruction += '    Q: 045'

                else:
                    outputPrint += 'Does not require MODRM' + '\n'
                    instruction += li[0]

                    if li[2] == 'o':
                        # 'Op Encoding O'
                        implemented = True
                        displace = li[3]
                        instruction += GLOBAL_REGISTER_NAMES[int(hex(int(instruction_bytes, 16) - displace), 16)]
                        # instruction += '    Q: 046'

                    elif li[2] == 'oi':
                        'Op Encoding oi'
                        implemented = True
                        displace = li[3]
                        instruction += GLOBAL_REGISTER_NAMES[int(hex(int(instruction_bytes, 16) - displace), 16)]
                        immed = ''
                        for y in range(4):
                            immed += "%02X" % b[i]
                            instruction_bytes += ' ' + "%02X" % b[i]
                            i += 1
                        instruction += ', 0x' + ''.join(reversed([immed[i:i+2] for i in range(0, len(immed), 2)]))
                        # instruction += '    Q: 047'

                    elif li[2] == 'id':
                        # 'Op Encoding id'
                        implemented = True
                        immed = ''
                        for y in range(li[3]):
                            immed += "%02X" % b[i]
                            instruction_bytes += ' ' + "%02X" % b[i]
                            i += 1
                        if opcode == 0xC2 or opcode == 0xCA:
                            instruction += '0x' + ''.join(reversed([immed[i:i + 2] for i in range(0, len(immed), 2)]))
                        else:
                            instruction += 'eax, 0x' + ''.join(reversed([immed[i:i+2] for i in range(0, len(immed), 2)]))
                        #instruction += '    Q: 003'

                    elif li[2] == 'zo':
                        # 'Op Encoding zo'
                        implemented = True
                        if i < len(b) and b[i] == 0xA7:
                            instruction_bytes += " %02X" % b[i]
                            i += 1
                        # instruction += '    Q: 005'

                    elif li[2] == 'd':
                        # 'Op Encoding d'
                        implemented = True
                        if opcode == 0xE8 or opcode == 0xE9:
                            instruction += 'offset_'
                            immed = ''
                            if (i + li[3]) < len(b):
                                for y in range(li[3]):
                                    immed += "%02X" % b[i]
                                    instruction_bytes += ' ' + "%02X" % b[i]
                                    i += 1
                                immed = ''.join(reversed([immed[i:i + 2] for i in range(0, len(immed), 2)]))
                                origin = i + int(immed, 16)
                                instruction += "%02X" % origin + 'h'
                                labelList["%08X" % origin] = 'offset from 0x%08X' % orig_index
                        else:
                            immed = ''
                            for y in range(li[3]):
                                immed += "%02X" % b[i]
                                instruction_bytes += ' ' + "%02X" % b[i]
                                i += 1
                            if li[3] == 1:
                                if int(immed, 16) <= 127:
                                    origin = i + int(immed, 16)
                                else:
                                    origin = i - int(immed, 16)
                            elif li[3] == 4:
                                if int(immed, 16) <= 2147483647:
                                    origin = i + int(immed, 16)
                                else:
                                    origin = i - int(immed, 16)
                            instruction += "%02X" % origin + 'h'
                            labelList["%08X" % origin] = 'offset from 0x%08X' % orig_index
                        # instruction += '    Q: 048'

                    else:
                        outputPrint += 'modify to complete the instruction and consume the appropriate bytes'  + '\n'

                if implemented:
                    outputPrint += 'Adding to list ' + instruction + '\n'
                    space = ''
                    outputPrint += 'space ' + str(i - orig_index) + '\n'
                    for y in range(36 - ((i - orig_index)*3)):
                        space += ' '
                    outputList["%08X" % orig_index] = instruction_bytes + space + instruction
                else:
                    outputList["%08X" % orig_index] = 'db %02x' % (int(opcode) & 0xff)

            # except:
            else:
                outputList["%08X" % orig_index] = 'db %02x' % (int(opcode) & 0xff)
                i = orig_index
        else:
            outputList["%08X" % orig_index] = 'db %02x' % (int(opcode) & 0xff)

        # Hint this is here for a reason, but is this the only spot
        # such a check is required in?
        if i > len(b):
            break

    # writeLineFile(outputPrint)
    saveToFile(outputList, labelList)
    # saveToFile(labelList)
    # print(labelList)
    # print(outputPrint)
    # printDisassm(outputList, labelList)


def getfile(filename):	
    with open(filename, 'rb') as f:
        a = f.read()
    return a		

def main():

    import sys
    if len(sys.argv) < 2:
        print("Please enter filename.")
        sys.exit(0)
    else:
        binary = getfile(sys.argv[1])

    disassemble(binary)


if __name__ == '__main__':
    main()
