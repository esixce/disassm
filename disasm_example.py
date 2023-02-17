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

GLOBAL_81_INDEXES = ['add    ', '', '', '', '', '', 'xor    ', 'cmp    ']
GLOBAL_FF_INDEXES = ['inc    ', '', 'call   ', '', 'jmp    ', '', 'push   ', '']
#
# Key is the opcode
# value is a list of useful information
GLOBAL_OPCODE_MAP = {

    # duplicates
    0x81: ['tbd', True, 'mi'],     # GLOBAL_81_INDEXES
    # 0x81: ['add ', True, 'mi'],   # /0
    # 0x81: ['xor ', True, 'mi'],   # /6
    # 0x81: ['cmp ', True, 'mi'],   # /7

    0xFF: ['tbd', True, 'm'],      # GLOBAL_FF_INDEXES
    # 0xFF: ['inc ', True, 'm'],    # /0
    # 0xFF: ['call ', True, 'm'],   # /2
    # 0xFF: ['jmp ', True, 'm'],    # /4    # jmp r/m32
    # 0xFF: ['push ', True, 'm'],   # /6

    # add
    0x05: ['add    eax, ', False, 'id'],
    0x01: ['add    ', True, 'mr'],
    0x03: ['add    ', True, 'rm'],

    # sub


    # or

    # xor
    0x35: ['xor    ', False, 'id'],    # DOUBLE CHECK
    0x31: ['xor    ', True, 'mr'],
    0x33: ['xor    ', True, 'rm'],

    # and


    # not


    # ret
    0xC3: ['retn   ', False, 'zo'],
    0xCB: ['retf   ', False, 'zo'],
    0xC2: ['retn   ', False, 'id'],
    0xCA: ['retf   ', False, 'id'],

    # jmp


    # jz/jnz
    0x74:   ['jz     ', False, 'd', 1],        # jz rel8
    0x0F84: ['jz     ', False, 'd', 4],        # jz rel32
    0x75:   ['jnz    ', False, 'd', 1],       # jnz rel8
    0x0F85: ['jnz    ', False, 'd', 4],       # jnz rel32

    # jmp
    0xEB: ['jmp    ', False, 'd', 1],             # jmp rel8
    0xE9: ['jmp    ', False, 'd', 4],             # jmp rel32
    # jmp [ disp32 ]
    # jmp [ r/m32 + disp8 ]
    # jmp [ r/m32 + disp32 ]
    # jmp [ r/m32*1 + disp32 ]
    # jmp [ r/m32*2 + disp32 ]
    # jmp [ r/m32*4 + disp32 ]
    # jmp [ r/m32*8 + disp32 ]
    # jmp [ r/m32*1 + r32 + disp32 ]
    # jmp [ r/m32*2 + r32 + disp32 ]
    # jmp [ r/m32*4 + r32 + disp32 ]
    # jmp [ r/m32*8 + r32 + disp32 ]

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
    0x68: ['push   ', False, 'id'],
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
    0x3D: ['cmp    ', False, 'id'],
    0x39: ['cmp    ', True, 'mr'],
    0x3B: ['cmp    ', True, 'rm'],

    # repne cmpsd


    # test


    # lea
    0x8D: ['lea    ', True, 'rm'],

    # clflush


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

    # movsd



    # nop


    # idiv


}

GLOBAL_REGISTER_NAMES = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

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
    f = open("output.txt", "w")
    for addr in sorted(output):
        f.write('%s: %s' % (addr, output[addr]) + '\n')
    f.close()

def printDisassm(output):

    # Good idea to add a "global label" structure...
    # TODO can check to see if "addr" is in it for a branch reference

    for addr in sorted(output):
        print('%s: %s' % (addr, output[addr]))

def disassemble(b):

    # manage final output key is address
    outputList = {}

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
            # print('Found valid opcode')
            if 1:                                       # TRUE
                li = GLOBAL_OPCODE_MAP[opcode]
                # print('Index -> %d' % i)
                if li[1]:
                    # print('REQUIRES MODRM BYTE')
                    modrm = b[i]
                    instruction_bytes += ' '
                    instruction_bytes += "%02x" % b[i]

                    i += 1      # we've consumed it now
                    mod, reg, rm = parseMODRM(modrm)

                    if mod == 3:
                        implemented = True
                        # print('r/m32 operand is direct register')
                        # print('li[2] ' + li[2])
                        if li[2] == 'mr':
                            instruction += li[0]
                            instruction += GLOBAL_REGISTER_NAMES[rm]
                            instruction += ', '
                            instruction += GLOBAL_REGISTER_NAMES[reg]
                        elif li[2] == 'rm':
                            instruction += li[0]
                            instruction += GLOBAL_REGISTER_NAMES[reg]
                            instruction += ', '
                            instruction += GLOBAL_REGISTER_NAMES[rm]
                        elif li[2] == 'mi':
                            # print(reg)
                            # TODO
                            disp = ''
                            for y in range(4):
                                disp += "%02x" % b[i]
                                i += 1
                            instruction += GLOBAL_81_INDEXES[reg] + GLOBAL_REGISTER_NAMES[rm] + ', [0x'
                            instruction += ''.join(reversed([disp[i:i+2] for i in range(0, len(disp), 2)])) + ']'

                    elif mod == 2:
                        implemented = True
                        # 'r/m32 operand is [ reg + disp32 ]

                        instruction += li[0] + GLOBAL_REGISTER_NAMES[reg]
                        # will need to parse the displacement32
                        disp = ''
                        for y in range(4):
                            disp += "%02x" % b[i]
                            i += 1
                        instruction += ', [ebp + 0x'
                        instruction += ''.join(reversed([disp[i:i+2] for i in range(0, len(disp), 2)])) + ']'

                    elif mod == 1:
                        # Uncomment next line when you've implemented this
                        implemented = True
                        # 'r/m32 operand is [ reg + disp8 ]

                        instruction += li[0] + GLOBAL_REGISTER_NAMES[reg]
                        # will need to parse the displacement8
                        instruction += ', [ebp + 0x' + "%02x" % b[i] + ']'
                        i += 1

                    elif mod == 0:
                        # print('"%02x" % b[i-2] ' + str("%02x" % b[i-2]))
                        # print('"%02x" % b[i-1] ' + str("%02x" % b[i-1]))
                        # print('mod ' + str(mod))
                        # print('reg ' + str(reg))
                        # print('rm ' + str(rm))
                        if rm == 7:
                            # 'r/m32 operand is [reg]
                            implemented = True
                            instruction += li[0] + '['
                            instruction += GLOBAL_REGISTER_NAMES[rm] + '], '
                            instruction += GLOBAL_REGISTER_NAMES[reg]
                            # TODO in progress

                        elif rm == 6:
                            # 'r/m32 operand is [reg]
                            implemented = True
                            instruction += li[0]
                            instruction += GLOBAL_REGISTER_NAMES[reg] + ', ['
                            instruction += GLOBAL_REGISTER_NAMES[rm] + ']'

                        elif rm == 5:
                            # print('r/m32 operand is [disp32]
                            implemented = True
                            instruction += li[0] + GLOBAL_REGISTER_NAMES[reg] + ', [0x'
                            disp = ''
                            for y in range(4):
                                disp += "%02x" % b[i]
                                i += 1
                            instruction += ''.join(reversed([disp[i:i+2] for i in range(0, len(disp), 2)])) + '] WARNING'

                        elif rm == 4:
                            # Uncomment next line when you've implemented this
                            # implemented = True
                            print('Indicates SIB byte required -> please implement')

                        elif rm == 1:
                            # TODO in validate
                            # 'r/m32 operand is [reg]
                            implemented = True
                            if li[0] != 'tbd':
                                instruction += li[0]
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + '], '
                                instruction += GLOBAL_REGISTER_NAMES[reg]

                            else:
                                instruction += GLOBAL_FF_INDEXES[reg]
                                instruction += '[' + GLOBAL_REGISTER_NAMES[rm] + ']'

                        elif rm == 0:
                            # 'r/m32 operand is [reg]
                            implemented = True
                            instruction += li[0] + '['
                            instruction += GLOBAL_REGISTER_NAMES[rm] + '], '
                            instruction += GLOBAL_REGISTER_NAMES[reg]

                        else:
                            # Uncomment next line when you've implemented this
                            print('r/m32 operand is [reg] -> please implement')

                    else:
                        print('ERROR')

                    if implemented:
                        # print('Adding to list ' + instruction)
                        outputList["%08X" % orig_index] = instruction_bytes + '         ' + instruction
                    else:
                        outputList["%08X" % orig_index] = 'db %02x' % (int(opcode) & 0xff)
                else:
                    # print('Does not require MODRM')

                    if li[2] == 'o':
                        # print('Op Encoding O')
                        implemented = True
                        displace = li[3]
                        instruction += li[0]
                        instruction += GLOBAL_REGISTER_NAMES[int(hex(int(instruction_bytes, 16) - displace), 16)]

                    elif li[2] == 'oi':
                        # print('Op Encoding oi')
                        implemented = True
                        displace = li[3]
                        instruction += li[0]
                        instruction += GLOBAL_REGISTER_NAMES[int(hex(int(instruction_bytes, 16) - displace), 16)]
                        immed = ''
                        for y in range(4):
                            immed += "%02x" % b[i]
                            i += 1
                        instruction += ', 0x' + ''.join(reversed([immed[i:i+2] for i in range(0, len(immed), 2)]))

                    elif li[2] == 'id':
                        # print('Op Encoding id')
                        implemented = True
                        instruction += li[0]
                        immed = ''
                        for y in range(2):
                            immed += "%02x" % b[i]
                            i += 1
                        instruction += '0x' + ''.join(reversed([immed[i:i+2] for i in range(0, len(immed), 2)]))

                    elif li[2] == 'zo':
                        # print('Op Encoding zo')
                        # TODO in progress
                        implemented = True
                        instruction += li[0]

                    elif li[2] == 'd':
                        # print('Op Encoding d')
                        implemented = True
                        # TODO NOT WORKING offset
                        # The rel8 follows the opcode and is relative to the end of the current instruction. The target
                        # address is the address of the current instruction + the instruction size + displacement. Due
                        # to the rel8, the displacement is sign extended to 32 bits. Note that our counter is tracking
                        # the address of each instruction.
                        # target = counter + instr_len + sign_extend(rel8)
                        immed = ''
                        for y in range(li[3]):
                            immed += "%02x" % b[i]
                            i += 1
                        instruction += li[0] + 'offset_'
                        instruction += ''.join(reversed([immed[i:i+2] for i in range(0, len(immed), 2)])) + 'h WARNING'

                    else:
                        print('modify to complete the instruction and consume the appropriate bytes')
                        # print('li[2]' + li[2])
                        # modify to complete the instruction and
                        # consume the appropriate bytes

                    if implemented:
                        # print('Adding to list ' + instruction)
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

    printDisassm(outputList)
    saveToFile(outputList)

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
