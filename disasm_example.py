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
    # 0xFF: ['call ', True, 'm'],    # /2
    # 0xFF: ['jmp  ', True, 'm'],    # /4
    # 0xFF: ['push ', True, 'm'],    # /6

    0xF7: ['tbd', True, 'm'],      # GLOBAL_F7_INDEXES
    # 0xF7: ['test   ', True, 'mi'],  # /0
    # 0xF7: ['not    ', True, 'm'],   # /2
    # 0xF7: ['idiv   ', True, 'm'],   # /7

    # not
    # see duplicates

    # idiv
    # see duplicates

    # add
    0x05: ['add    eax, ', False, 'id', 4],
    0x01: ['add    ', True, 'mr'],
    0x03: ['add    ', True, 'rm'],

    # sub
    0x2D: ['sub    ', False, 'id', 4],
    0x09: ['sub    ', True, 'mr'],
    0x0B: ['sub    ', True, 'rm'],

    # or
    0x0D: ['or     ', False, 'id', 4],
    0x29: ['or     ', True, 'mr'],
    0x2B: ['or     ', True, 'rm'],

    # xor
    0x35: ['xor    ', False, 'id', 4],         # DOUBLE CHECK
    0x31: ['xor    ', True, 'mr'],
    0x33: ['xor    ', True, 'rm'],

    # and
    0x25: ['and    ', False, 'id', 4],
    0x21: ['and    ', True, 'mr'],
    0x23: ['and    ', True, 'rm'],

    # ret
    0xC3: ['retn   ', False, 'zo'],
    0xCB: ['retf   ', False, 'zo'],
    0xC2: ['retn   ', False, 'id', 2],
    0xCA: ['retf   ', False, 'id', 2],

    # jz/jnz
    0x74:   ['jz     ', False, 'd', 1],        # jz rel8
    0x0F84: ['jz     ', False, 'd', 4],        # jz rel32
    0x75:   ['jnz    ', False, 'd', 1],       # jnz rel8
    0x0F85: ['jnz    ', False, 'd', 4],       # jnz rel32

    # jmp
    0xEB: ['jmp    ', False, 'd', 1],             # jmp rel8
    0xE9: ['jmp    ', False, 'd', 4],             # jmp rel32

    # call
    0xE8: ['call   ', False, 'd', 4],

    # pop
    # 58+rd pop r32, False, 'o'
    0x58: ['pop    ', False, 'o', 0x58],
    0x59: ['pop    ', False, 'o', 0x58],
    0x5A: ['pop    ', False, 'o', 0x58],
    0x5B: ['pop    ', False, 'o', 0x58],
    0x5C: ['pop    ', False, 'o', 0x58],
    0x5D: ['pop    ', False, 'o', 0x58],
    0x5E: ['pop    ', False, 'o', 0x58],
    0x5F: ['pop    ', False, 'o', 0x58],

    # push
    0x68: ['push   ', False, 'id', 4],
    # 50+rd push r32, False, 'o'
    0x57: ['push   ', False, 'o', 0x50],
    0x56: ['push   ', False, 'o', 0x50],
    0x55: ['push   ', False, 'o', 0x50],
    0x54: ['push   ', False, 'o', 0x50],
    0x53: ['push   ', False, 'o', 0x50],
    0x52: ['push   ', False, 'o', 0x50],
    0x51: ['push   ', False, 'o', 0x50],
    0x50: ['push   ', False, 'o', 0x50],

    # dec
    # 0x48 + rd: ['dec    ', False, 'o'],
    0x48: ['dec    ', False, 'o', 0x48],
    0x49: ['dec    ', False, 'o', 0x48],
    0x4A: ['dec    ', False, 'o', 0x48],
    0x4B: ['dec    ', False, 'o', 0x48],
    0x4C: ['dec    ', False, 'o', 0x48],
    0x4D: ['dec    ', False, 'o', 0x48],
    0x4E: ['dec    ', False, 'o', 0x48],
    0x4F: ['dec    ', False, 'o', 0x48],

    # inc
    # 0x40 + rd: ['inc    ', False, 'o'],
    0x40: ['inc    ', False, 'o', 0x40],
    0x41: ['inc    ', False, 'o', 0x40],
    0x42: ['inc    ', False, 'o', 0x40],
    0x43: ['inc    ', False, 'o', 0x40],
    0x44: ['inc    ', False, 'o', 0x40],
    0x45: ['inc    ', False, 'o', 0x40],
    0x46: ['inc    ', False, 'o', 0x40],
    0x47: ['inc    ', False, 'o', 0x40],

    # cmp
    0x3D: ['cmp    ', False, 'id', 4],
    0x39: ['cmp    ', True, 'mr'],
    0x3B: ['cmp    ', True, 'rm'],

    # test
    0xA9: ['test   ', False, 'id', 4],
    0x85: ['test   ', True, 'mr'],

    # lea
    0x8D: ['lea    ', True, 'rm'],

    # mov
    0x89: ['mov    ', True, 'mr'],
    0x8B: ['mov    ', True, 'rm'],
    0xC7: ['mov    ', True, 'mi'],
    # 0xB8 + rd: ['mov ', False, 'oi'],
    0xB8: ['mov    ', False, 'oi', 0xB8],
    0xB9: ['mov    ', False, 'oi', 0xB8],
    0xBA: ['mov    ', False, 'oi', 0xB8],
    0xBB: ['mov    ', False, 'oi', 0xB8],
    0xBC: ['mov    ', False, 'oi', 0xB8],
    0xBD: ['mov    ', False, 'oi', 0xB8],
    0xBE: ['mov    ', False, 'oi', 0xB8],
    0xBF: ['mov    ', False, 'oi', 0xB8],

    # nop
    0x0F: ['nop    ', True, 'm'],

    # movsd
    0xA5: ['movsd  ', False, 'zo'],

    # repne cmpsd repeat not equal

    # clflush
        # 0fae
}
# Duplicate Opcodes
GLOBAL_81_INDEXES = ['add    ', 'or     ', '', '', 'and    ', 'sub    ', 'xor    ', 'cmp    ']
GLOBAL_FF_INDEXES = ['inc    ', 'dec    ', 'call   ', '', 'jmp    ', '', 'push   ', '']
GLOBAL_F7_INDEXES = ['test   ', '', 'not    ', '', '', '', '', 'idiv   ']

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

def saveToFile(output):
    f = open("output.txt", "a")
    for addr in sorted(output):
        f.write('%s: %s' % (addr, output[addr]) + '\n')
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
            print('          %s: %s' % (addr, labelList[addr]))
        print('%s: %s' % (addr, output[addr]))

def twos_complement(hexstr, bits):
    value = int(hexstr, 16)
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value

def disassemble(b):

    # manage final output key is address
    outputList = {}
    labelList = {}
    outputPrint = ''

    i = 0

    while i < len(b):

        implemented = False
        opcode = b[i]	                        # current byte to work on
        instruction_bytes = "%02x" % b[i]       # making b[i] int and converting to 2hex
        instruction = ''
        orig_index = i
        
        i += 1

        # Hint this is here for a reason, but is this the only spot
        # such a check is required in?
        if i > len(b):
           break

        if isValidOpcode(opcode):
            outputPrint += 'Index -> %d' % i + ' 0x' + '%02x' % (i-1) + '\n'
            outputPrint += 'Found valid opcode ' + instruction_bytes + ' ' + GLOBAL_OPCODE_MAP[opcode][0] + '\n'
            outputPrint += 'opcode[2] ' + GLOBAL_OPCODE_MAP[opcode][2] + '\n'

            if 1:                                       # TRUE # TODO Check size
                li = GLOBAL_OPCODE_MAP[opcode]
                if li[1]:
                    outputPrint += 'REQUIRES MODRM BYTE' + '\n'

                    modrm = b[i]
                    mod, reg, rm = parseMODRM(modrm)

                    if li[0] != 'tbd':
                        instruction += li[0]
                    else:
                        if instruction_bytes == '81':
                            instruction += GLOBAL_81_INDEXES[reg]
                        elif instruction_bytes == 'FF':
                            instruction += GLOBAL_FF_INDEXES[reg]
                        elif instruction_bytes == 'F7':
                            instruction += GLOBAL_F7_INDEXES[reg]

                    instruction_bytes += ' '
                    instruction_bytes += "%02x" % b[i]
                    i += 1      # we've consumed it now

                    if rm == 4 and b[i] == 0x24:  # TODO  skipped byte on ESI???? b[i] == 0x24
                        i += 1

                    outputPrint += 'mod ' + str(mod) + '\n'
                    outputPrint += 'reg ' + str(reg) + '\n'
                    outputPrint += 'rm ' + str(rm) + '\n'

                    # MOD 0 - 3 SWITCH
                    if mod == 3:
                        # 'r/m32 operand is direct register'
                        implemented = True

                        # R/M SWITCH
                        if li[2] == 'mr':
                            instruction += GLOBAL_REGISTER_NAMES[rm]
                            instruction += ', '
                            instruction += GLOBAL_REGISTER_NAMES[reg]

                        elif li[2] == 'rm':
                            instruction += GLOBAL_REGISTER_NAMES[reg]
                            instruction += ', '
                            instruction += GLOBAL_REGISTER_NAMES[rm]

                        elif li[2] == 'mi':
                            disp = ''
                            for y in range(4):
                                disp += "%02x" % b[i]
                                i += 1
                            instruction += GLOBAL_REGISTER_NAMES[rm] + ', 0x'
                            instruction += ''.join(reversed([disp[i:i+2] for i in range(0, len(disp), 2)]))

                    elif mod == 2:
                        implemented = True
                        # 'r/m32 operand is [ reg + disp32 ]

                        if rm == 4:         # R/M bits = 100
                            # 'r/m32 operand is [ reg * mult + disp32 ]
                            outputPrint += 'rm ' + str(rm) + ' therefore, SIB required.\n'
                            sib = b[i]
                            i += 1
                            scale, index, base = parseMODRM(sib)
                            outputPrint += 'scale ' + str(scale) + '\n'
                            outputPrint += 'index ' + str(index) + '\n'
                            outputPrint += 'base ' + str(base) + '\n'

                            # TODO RESTRUCTURE
                            if li[2] == 'rm':
                                instruction += GLOBAL_REGISTER_NAMES[reg] + ', ['
                                if b[i] == 0x33 or b[i] == 0x03 or index == 0 or index == 1 or index == 2 or index == 3 or index == 5 or index == 6 or index == 7:        # TODO  skipped byte on ESI???? b[i] == 0x24
                                    i -= 1
                                if not(scale == 0 and index == 6 and base == 3):    # TODO terrible
                                    i += 1
                                    instruction += GLOBAL_REGISTER_NAMES[base] + ' + '

                                instruction += GLOBAL_REGISTER_NAMES[index] + ' * ' + str(pow(2, scale))
                                disp = ''
                                for y in range(4):
                                    disp += "%02x" % b[i]
                                    i += 1
                                instruction += ' + 0x' + ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)])) + ']'
                                instruction += ' VWARNING!!!!!'

                                if b[i] == 0x33:        # TODO  skipped byte on ESI???? b[i] == 0x24
                                    i += 1

                            # TODO DELETE??
                            elif li[2] == 'mr':
                                i -= 1
                                # 'r/m32 operand is [ reg + disp32 ]
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                disp = ''
                                for y in range(4):
                                    disp += "%02x" % b[i]
                                    i += 1
                                instruction += ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)])) + '], '
                                instruction += GLOBAL_REGISTER_NAMES[reg]

                            # TODO DELETE??
                            elif li[2] == 'mi':
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'

                                i -= 1
                                disp = ''
                                for y in range(4):
                                    disp += "%02x" % b[i]
                                    i += 1
                                instruction += ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)])) + ']'

                                disp = ''
                                for y in range(4):
                                    disp += "%02x" % b[i]
                                    i += 1
                                instruction += ', 0x' + ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))

                        else:

                            # R/M SWITCH
                            if li[2] == 'mr':
                                # 'r/m32 operand is [ reg + disp32 ]
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                disp = ''
                                for y in range(4):
                                    disp += "%02x" % b[i]
                                    i += 1
                                instruction += ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)])) + '], '
                                instruction += GLOBAL_REGISTER_NAMES[reg]

                            elif li[2] == 'rm':
                                # 'r/m32 operand is [ reg + disp32 ]
                                instruction += GLOBAL_REGISTER_NAMES[reg] + ', ['
                                instruction += GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                disp = ''
                                for y in range(4):
                                    disp += "%02x" % b[i]
                                    i += 1
                                instruction += ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)])) + ']'

                            elif li[2] == 'mi':
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'

                                disp = ''
                                for y in range(4):
                                    disp += "%02x" % b[i]
                                    i += 1
                                instruction += ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)])) + ']'

                                disp = ''
                                for y in range(4):
                                    disp += "%02x" % b[i]
                                    i += 1
                                instruction += ', 0x' + ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))

                    elif mod == 1:
                        implemented = True
                        # 'r/m32 operand is [ reg + disp8 ]
                        if rm == 4:         # R/M bits = 100
                            # 'r/m32 operand is [ reg * mult + disp8 ]
                            outputPrint += 'rm ' + str(rm) + ' therefore, SIB required.\n'
                            sib = b[i]
                            i += 1
                            scale, index, base = parseMODRM(sib)
                            outputPrint += 'scale ' + str(scale) + '\n'
                            outputPrint += 'index ' + str(index) + '\n'
                            outputPrint += 'base ' + str(base) + '\n'

                            # TODO RESTRUCTURE
                            if li[2] == 'rm':
                                if b[i] == 0x33 or b[i] == 0x03:        # TODO  skipped byte on ESI???? b[i] == 0x24
                                    i -= 1
                                instruction += GLOBAL_REGISTER_NAMES[reg] + ', ['
                                if not(index == 6 and base == 3):    # TODO terrible
                                    i += 1
                                    instruction += GLOBAL_REGISTER_NAMES[base] + ' + '
                                instruction += GLOBAL_REGISTER_NAMES[index] + ' * ' + str(pow(2, scale))
                                instruction += ' + 0x' + "%02x" % b[i] + ']'
                                i += 1
                                instruction += ' TWARNING!!!!!!'

                            elif li[2] == 'mr':
                                i -= 1
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                instruction += "%02x" % b[i] + '], '
                                i += 1
                                instruction += GLOBAL_REGISTER_NAMES[reg]

                            elif li[2] == 'mi':
                                i -= 1
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                instruction += "%02x" % b[i] + '], '
                                i += 1
                                size = 4
                                disp = ''
                                for y in range(size):
                                     disp += "%02x" % b[i]
                                     i += 1
                                instruction += '0x' + ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))

                        else:

                            if li[2] == 'mr':
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                instruction += "%02x" % b[i] + '], '
                                i += 1
                                instruction += GLOBAL_REGISTER_NAMES[reg]

                            elif li[2] == 'rm':
                                instruction += GLOBAL_REGISTER_NAMES[reg]
                                instruction += ', [' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'

                                instruction += "%02x" % b[i] + ']'
                                i += 1
                                # if rm == 5 and b[i] == 0x00:  # TODO  skipped byte on EBP???? b[i] == 0x00
                                #    i += 1

                                # instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + '], '
                                # instruction += GLOBAL_REGISTER_NAMES[reg]

                            elif li[2] == 'mi':
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x'
                                instruction += "%02x" % b[i] + '], '    # TODO in validation
                                i += 1
                                size = 4
                                disp = ''
                                for y in range(size):
                                    disp += "%02x" % b[i]
                                    i += 1
                                instruction += '0x' + ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))

                            else:
                                outputPrint += 'Implement\n'

                    elif mod == 0:
                        implemented = True

                        #  Mod 0 Special case SWITCH
                        if rm == 5:         # R/M bits = 101
                            outputPrint += 'rm ' + str(rm) + ' therefore, special case\n'
                            # 'r/m32 operand is [disp32]

                            # R/M SWITCH
                            if li[2] == 'mr':
                                instruction += '[0x'
                                disp = ''
                                for y in range(4):
                                    disp += "%02x" % b[i]
                                    i += 1
                                instruction += ''.join(reversed([disp[i:i+2] for i in range(0, len(disp), 2)]))
                                instruction += '], ' + GLOBAL_REGISTER_NAMES[reg]

                            elif li[2] == 'rm':
                                instruction += GLOBAL_REGISTER_NAMES[reg]
                                instruction += ', [0x'
                                disp = ''
                                for y in range(4):
                                    disp += "%02x" % b[i]
                                    i += 1
                                instruction += ''.join(reversed([disp[i:i+2] for i in range(0, len(disp), 2)])) + ']'


                            elif li[2] == 'mi':
                                instruction += GLOBAL_REGISTER_NAMES[reg] + ', [0x'

                                disp = ''
                                for y in range(4):
                                    disp += "%02x" % b[i]
                                    i += 1
                                instruction += ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)])) + ']'

                                instruction += ', 0x'
                                disp = ''
                                for y in range(4):
                                    disp += "%02x" % b[i]
                                    i += 1
                                instruction += ''.join(reversed([disp[i:i+2] for i in range(0, len(disp), 2)]))

                                # TODO check all i += 1 locations

                        elif rm == 4:         # R/M bits = 100
                            outputPrint += 'rm ' + str(rm) + ' therefore, SIB required.\n'
                            sib = b[i]
                            # i += 1
                            scale, index, base = parseMODRM(sib)
                            outputPrint += 'scale ' + str(scale) + '\n'
                            outputPrint += 'index ' + str(index) + '\n'
                            outputPrint += 'base ' + str(base) + '\n'

                            # TODO RESTRUCTURE
                            if li[2] == 'rm':
                                instruction += GLOBAL_REGISTER_NAMES[reg] + ', '
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' * ' + str(pow(2, scale)) + ']'

                            elif li[2] == 'mr':
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' * ' + str(pow(2, scale)) + '], '
                                instruction += GLOBAL_REGISTER_NAMES[reg]

                            elif li[2] == 'mi':
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ' * ' + str(pow(2, scale)) + ']'
                                disp = ''
                                for y in range(4):
                                    disp += "%02x" % b[i]
                                    i += 1
                                instruction += ', 0x' + ''.join(reversed([disp[i:i + 2] for i in range(0, len(disp), 2)]))

                        else:
                            outputPrint += 'rm ' + str(rm) + ' therefore, NOT special case\n'
                            # 'r/m32 operand is [reg]
                            implemented = True

                            # R/M SWITCH
                            if li[2] == 'rm':
                                instruction += GLOBAL_REGISTER_NAMES[reg]
                                instruction += ', [' + GLOBAL_REGISTER_NAMES[rm] + ']'

                            elif li[2] == 'mr':
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + '], '
                                instruction += GLOBAL_REGISTER_NAMES[reg]

                                # TODO HERE
                                if rm == 4 and b[i] == 0x24:  # TODO  skipped byte on edp???? b[i] == 0x24
                                    i += 1
                                # if b[i] == 0x24 or b[i] == 0x00:       # TODO  skipped byte????
                                #    i += 1

                            elif li[2] == 'mi':
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ']'
                                disp = ''
                                for y in range(4):
                                    disp += "%02x" % b[i]
                                    i += 1
                                instruction += ', 0x' + ''.join(reversed([disp[i:i+2] for i in range(0, len(disp), 2)]))

                        # TODO TAKEN CODE

                    else:
                        outputPrint += 'ERROR' + '\n'

                else:
                    outputPrint += 'Does not require MODRM' + '\n'
                    instruction += '   ' + li[0]

                    if li[2] == 'o':
                        # print('Op Encoding O')
                        implemented = True
                        displace = li[3]
                        instruction += GLOBAL_REGISTER_NAMES[int(hex(int(instruction_bytes, 16) - displace), 16)]

                    elif li[2] == 'oi':
                        # print('Op Encoding oi')
                        implemented = True
                        displace = li[3]
                        instruction += GLOBAL_REGISTER_NAMES[int(hex(int(instruction_bytes, 16) - displace), 16)]
                        immed = ''
                        for y in range(4):
                            immed += "%02x" % b[i]
                            i += 1
                        instruction += ', 0x' + ''.join(reversed([immed[i:i+2] for i in range(0, len(immed), 2)]))

                    elif li[2] == 'id':
                        # print('Op Encoding id')
                        # TODO PROBLEM
                        implemented = True
                        immed = ''
                        for y in range(li[3]):
                            immed += "%02x" % b[i]
                            i += 1
                        instruction += '0x' + ''.join(reversed([immed[i:i+2] for i in range(0, len(immed), 2)]))

                    elif li[2] == 'zo':
                        # print('Op Encoding zo')
                        # TODO in progress
                        implemented = True

                    elif li[2] == 'd':
                        # print('Op Encoding d')
                        implemented = True
                        # TODO NOT WORKING offset
                        # The rel8 follows the opcode and is relative to the end of the current instruction. The target
                        # address is the address of the current instruction + the instruction size + displacement. Due
                        # to the rel8, the displacement is sign extended to 32 bits. Note that our counter is tracking
                        # the address of each instruction.
                        # target = counter + instr_len + sign_extend(rel8)
                        # TODO jz op 74 near =
                        instruction += 'offset_'
                        immed = ''
                        for y in range(li[3]):
                            instruction_bytes += " %02x" % b[i]
                            immed += "%02x" % b[i]
                            i += 1
                        immed = ''.join(reversed([immed[i:i+2] for i in range(0, len(immed), 2)]))
                        if int(immed, 16) <= 127:
                            label = i + int(immed, 16)
                        else:
                            label = i - int(immed, 16)

                        # TODO twos complement

                        instruction += "%08X" % label + 'h'
                        labelList["%08X" % label] = 'offset from 0x%08X' % orig_index

                    else:
                        outputPrint += 'modify to complete the instruction and consume the appropriate bytes'  + '\n'

                if implemented:
                    outputPrint += 'Adding to list ' + instruction + '\n'
                    outputList["%08X" % orig_index] = instruction_bytes + '            ' + instruction
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

    writeLineFile(outputPrint)
    saveToFile(outputList)
    printDisassm(outputList, labelList)

def getfile(filename):	
    with open(filename, 'rb') as f:
        a = f.read()
    return a		

def main():
    #
    # Consider using:
    # import argparse
    #
    # parser = argparse.ArgumentParser()
    # parser.add_argument('-e', '--examplearg', help='Shows an example usage', dest='examplename', required=True)
    # args = parser.parse_args()
    #
    # access the value using:
    # if args.examplename != None:
    #     print("Passed in value %s" % args.examplename)

    import sys
    if len(sys.argv) < 2:
        print("Please enter filename.")
        sys.exit(0)
    else:
        binary = getfile(sys.argv[1])

    disassemble(binary)


if __name__ == '__main__':
    main()
