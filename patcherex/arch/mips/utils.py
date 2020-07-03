from patcherex.utils import *
import keystone


def capstone_to_asm(instruction):
    return instruction.mnemonic + " " + instruction.op_str.replace('{', '{{').replace('}', '}}')


def disassemble(code, offset=0x0, bits=32):
    if bits == 32:
        md = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32)
    elif bits == 64:
        md = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64)
    else:
        raise Exception("disassemble(): Unsupported bits %d." % bits)

    md.detail = True
    if isinstance(code, str):
        code = bytes(map(ord, code))
    return list(md.disasm(code, offset))


def compile_jmp(origin, target, bits=32):
    jmp_str = '''
        j {target}
    '''.format(**{'target': hex(int(target))})
    return compile_asm(jmp_str, base=origin, bits=bits)


def compile_asm(code, base=None, name_map=None, bits=32):
    # print "=" * 10
    # print code
    # if base != None: print hex(base)
    # if name_map != None: print {k: hex(v) for k,v in name_map.iteritems()}
    try:
        if name_map is not None:
            code = code.format(**name_map)  # compile_asm
        else:
            code = re.subn(r'{.*?}', "0x41414141", code)[0]  # solve symbols
    except KeyError as e:
        raise UndefinedSymbolException(str(e))
    try:
        ks = keystone.Ks(keystone.KS_ARCH_MIPS, keystone.KS_MODE_BIG_ENDIAN | keystone.KS_MODE_MIPS32)
        encoding, count = ks.asm(code, base)
    except keystone.KsError as e:
        print("ERROR: %s" % e)  # TODO raise some error
    return bytes(encoding)


def get_nasm_c_wrapper_code(function_symbol, get_return=False, debug=False):
    # TODO maybe with better calling convention on llvm this can be semplified
    wcode = []
    # wcode.append("pusha")
    # TODO add param list handling, right two params in ecx/edx are supported
    '''
    assert len(param_list) <= 2 # TODO support more parameters
    if len(param_list) == 1:
        wcode.append("mov ecx, %s" % param_list[0])
    if len(param_list) == 2:
        wcode.append("mov ecx, %s" % param_list[0])
        wcode.append("mov edx, %s" % param_list[1])
    '''
    # if debug:
    #     wcode.append("int 0x3")
    wcode.append("j {%s}" % function_symbol)
    # if get_return:
    #     wcode.append("mov [esp+28], eax") #FIXME check
    # wcode.append("popa")

    return "\n".join(wcode)


def compile_c(code, optimization='-Oz', name_map=None, compiler_flags="-m32"):
    # TODO symbol support in c code
    with tempdir() as td:
        code_filename = os.path.join(td, "code.c")
        object_filename = os.path.join(td, "code.o")
        bin_filename = os.path.join(td, "code.bin")

        fp = open(code_filename, 'w')
        fp.write(code)
        fp.close()

        res = exec_cmd("clang -nostdlib -target mips-linux-gnu -ffreestanding %s -o %s -c %s %s"
                       % (optimization, object_filename, code_filename, compiler_flags), shell=True)
        if res[2] != 0:
            print("CLang error:")
            print(res[0])
            print(res[1])
            fp = open(code_filename, 'r')
            fcontent = fp.read()
            fp.close()
            print("\n".join(["%02d\t%s" % (i + 1, l) for i, l in enumerate(fcontent.split("\n"))]))
            raise CLangException
        res = exec_cmd("mips-linux-gnu-objcopy -O binary -j .text %s %s" % (object_filename, bin_filename),
                       shell=True)
        if res[2] != 0:
            print("objcopy error:")
            print(res[0])
            print(res[1])
            raise ObjcopyException
        fp = open(bin_filename, "rb")
        compiled = fp.read()
        fp.close()
    return compiled
