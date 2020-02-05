# coding=utf-8
from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.program.model.symbol import RefType, SourceType
from common import *
from vx_structs import *
import string


# The Python module that Ghidra directly launches is always called __main__.  If we import
# everything from that module, this module will behave as if Ghidra directly launched it.
from __main__ import *


function_name_key_words = ['bzero', 'usrInit', 'bfill']

need_create_function = [
    0x04,
    0x05
]

# Prepare VxWorks symbol types



function_name_chaset = string.letters
function_name_chaset += string.digits
function_name_chaset += "_:.<>,*"  # For C++
function_name_chaset += "()~+-=/%"  # For C++ special eg operator+(ZafBignumData const &,long)
ghidra_builtin_types = [
    'undefined',
    'byte',
    'uint',
    'ushort',
    'bool',
    'complex16',
    'complex32',
    'complex8',
    'doublecomplex',
    'dwfenc',
    'dword',
    'filetime',
    'float10',
    'float16',
    'float2',
    'float4',
    'float8',
    'floatcomplex',
    'guid',
    'imagebaseoffset32',
    'imagebaseoffset64',
    'int16',
    'int3',
    'int5',
    'int6',
    'int7',
    'long',
    'longdouble',
    'longdoublecomplex',
    'longlong',
    'mactime',
    'prel31',
    'qword',
    'sbyte',
    'schar',
    'sdword',
    'segmentedcodeaddress',
    'shiftedaddress',
    'sqword',
    'sword',
    'wchar16',
    'wchar32',
    'uchar',
    'uint16',
    'uint3',
    'uint5',
    'uint6',
    'uint7',
    'ulong',
    'ulonglong',
    'undefined1',
    'undefined2',
    'undefined3',
    'undefined4',
    'undefined5',
    'undefined6',
    'undefined7',
    'undefined8',
    'wchar_t',
    'word'
]


def check_is_func_name(function_name):
    """ Check target string is match function name format.

    :param function_name: string to check.
    :return: True if string is match function name format, False otherwise.
    """
    # function name length should less than 512 byte
    if len(function_name) > 512:
        return False

    for c in function_name:
        if (c in function_name_chaset) is False:
            return False

    if function_name.lower() in ghidra_builtin_types:
        return False

    return True


def demangle_function(demangle_string):
    function_name = None
    function_return = None
    function_parameters = None
    function_name_end = len(demangle_string) - 1

    # get parameters
    index = len(demangle_string) - 1
    if demangle_string[-1] == ')':
        # have parameters
        parentheses_count = 0
        while index >= 0:
            if demangle_string[index] == ')':
                parentheses_count += 1

            elif demangle_string[index] == '(':
                parentheses_count -= 1

            index -= 1

            if parentheses_count == 0:
                break

        function_name_end = index

    # get function name
    while index >= 0:
        if demangle_string[index] == ' ':
            temp_data = demangle_string[index + 1:function_name_end + 1]
            if temp_data == "*":
                function_name_end = index
                index -= 1

            elif check_is_func_name(temp_data):
                function_name = temp_data
                break

            else:
                function_name_end = index
                index -= 1

        elif index == 0:
            if demangle_string[function_name_end] == " ":
                temp_data = demangle_string[index:function_name_end]
            else:
                temp_data = demangle_string[index:function_name_end + 1]
            if check_is_func_name(temp_data):
                function_name = temp_data
            break

        else:
            index -= 1

    function_name_start = index
    function_parameters = demangle_string[function_name_end + 1:]

    if index != 0:
        # get function return
        function_return = demangle_string[:function_name_start]

    return function_return, function_name, function_parameters


def demangled_symbol(symbol_string):
    sym_demangled_name = None
    sym_demangled = None
    if can_demangle:
        try:
            sym_demangled = demangler.demangle(symbol_string, True)

            if not sym_demangled:
                # some mangled function name didn't start with mangled prefix
                sym_demangled = demangler.demangle(symbol_string, False)

        except DemangledException as err:
            logger.debug("DemangledException: symbol_string: {}, reason:{}".format(symbol_string, err))

        try:
            if not sym_demangled:
                # Temp fix to handle _ prefix function name by remove _ prefix before demangle
                sym_demangled = demangler.demangle(symbol_string[1:], False)

        except DemangledException as err:
            logger.debug("DemangledException: symbol_string: {}, reason:{}".format(symbol_string, err))

        if sym_demangled:
            sym_demangled_name = sym_demangled.getSignature(False)

        if sym_demangled_name:
            logger.debug("sym_demangled_name: {}".format(sym_demangled_name))

    return sym_demangled_name


def add_symbol(symbol_name, symbol_name_address, symbol_address, symbol_type):
    symbol_address = toAddr(symbol_address)
    symbol_name_string = symbol_name

    # Get symbol_name
    if symbol_name_address:
        symbol_name_address = toAddr(symbol_name_address)
        if getDataAt(symbol_name_address):
            logger.debug("removeDataAt: {}".format(symbol_name_address))
            removeDataAt(symbol_name_address)

        try:
            symbol_name_string = createAsciiString(symbol_name_address).getValue()
            logger.debug("symbol_name_string: {}".format(symbol_name_string))

        except CodeUnitInsertionException as err:
            logger.error("Got CodeUnitInsertionException: {}".format(err))

        except:
            return

    if getInstructionAt(symbol_address):
        logger.debug("removeInstructionAt: {}".format(symbol_address))
        removeInstructionAt(symbol_address)

    # Demangle symName
    try:
        # Demangle symName
        sym_demangled_name = demangled_symbol(symbol_name_string)

        if symbol_name_string and (symbol_type in need_create_function):
            logger.debug("Start disassemble function {} at address {}".format(symbol_name_string,
                                                                              symbol_address.toString()))
            disassemble(symbol_address)
            function = createFunction(symbol_address, symbol_name_string)
            if function:
                function.setName(symbol_name_string, SourceType.USER_DEFINED)

            else:
                # Add original symbol name
                createLabel(symbol_address, symbol_name_string, True)

            if function and sym_demangled_name:
                # Add demangled string to comment
                codeUnit = listing.getCodeUnitAt(symbol_address)
                codeUnit.setComment(codeUnit.PLATE_COMMENT, sym_demangled_name)
                # Rename function
                function_return, function_name, function_parameters = demangle_function(sym_demangled_name)
                logger.debug("Demangled function name is: {}".format(function_name))
                logger.debug("Demangled function return is: {}".format(function_return))
                logger.debug("Demangled function parameters is: {}".format(function_parameters))

                if function_name:
                    function.setName(function_name, SourceType.USER_DEFINED)
                    # Todo: Add parameters later
                # Add original symbol name
                createLabel(symbol_address, symbol_name_string, True)

        else:
            createLabel(symbol_address, symbol_name_string, True)
            if sym_demangled_name:
                codeUnit = listing.getCodeUnitAt(symbol_address)
                codeUnit.setComment(codeUnit.PLATE_COMMENT, sym_demangled_name)

    except Exception as err:
        logger.error("Create symbol failed: symbol_name:{}, symbol_name_address:{}, "
                     "symbol_address:{}, symbol_type:{} reason: {}".format(symbol_name_string,
                                                                           symbol_name_address,
                                                                           symbol_address,
                                                                           symbol_type, err))

    except:
        logger.debug("Create symbol failed: symbol_name:{}, symbol_name_address:{}, "
                     "symbol_address{}, symbol_type{} with Unknown error".format(symbol_name_string,
                                                                                 symbol_name_address,
                                                                                 symbol_address,
                                                                                 symbol_type))


def fix_symbol_table_structs(symbol_table_start, symbol_table_end, vx_version):
    symbol_interval = 16
    dt = vx_5_symtbl_dt
    if vx_version == 6:
        symbol_interval = 20
        dt = vx_6_symtbl_dt

    # Create symbol table structs
    symbol_table_start_addr = toAddr(symbol_table_start)
    symbol_table_end_addr = toAddr(symbol_table_end)

    ea = symbol_table_start_addr
    sym_length = (symbol_table_end - symbol_table_start) // symbol_interval
    createLabel(symbol_table_start_addr, "vxSymTbl", True)
    clearListing(symbol_table_start_addr, symbol_table_end_addr)
    vx_symbol_array_data_type = ArrayDataType(dt, sym_length, dt.getLength())
    createData(symbol_table_start_addr, vx_symbol_array_data_type)


def is_vx_symbol_file(file_data, is_big_endian=True):
    # Check key function names
    for key_function in function_name_key_words:
        if key_function not in file_data:
            logger.debug("key function not found")
            return False

    if is_big_endian:
        return struct.unpack('>I', file_data[:4])[0] == len(file_data)

    else:
        return struct.unpack('<I', file_data[:4])[0] == len(file_data)


def get_symbol(symbol_name, symbom_prefix="_"):
        symbol = getSymbol(symbol_name, currentProgram.getGlobalNamespace())
        if not symbol and symbom_prefix:
            symbol = getSymbol("{}{}".format(symbom_prefix, symbol_name), currentProgram.getGlobalNamespace())

        return symbol


def get_function(function_name, function_prefix="_"):
    function = getFunction(function_name)
    if not function and function_prefix:
        function = getFunction("{}{}".format(function_prefix, function_name))

    return function


def fix_symbol_by_chains(head, tail, vx_version):
    symbol_interval = 0x10
    dt = vx_5_symtbl_dt
    if vx_version == 6:
        symbol_interval = 20
        dt = vx_6_symtbl_dt
    ea = head
    while True:
        prev_symbol_addr = toAddr(getInt(ea))
        symbol_name_address = getInt(ea.add(0x04))
        symbol_dest_address = getInt(ea.add(0x08))
        symbol_type = getByte(ea.add(symbol_interval - 2))
        create_struct(ea, dt)
        # Using symbol_address as default symbol_name.
        symbol_name = "0x{:08X}".format(symbol_dest_address)
        add_symbol(symbol_name, symbol_name_address, symbol_dest_address, symbol_type)

        if getInt(ea) == 0 or ea == tail:
            break

        ea = prev_symbol_addr

    return


def create_struct(data_address, data_struct, overwrite=True):
    if is_address_in_current_program(data_address) is False:
        logger.debug("Can't create data struct at {:#010x} with type {}".format(data_address.getOffset(), data_struct))
        return

    try:
        if overwrite:
            for offset in range(data_struct.getLength()):
                removeDataAt(data_address.add(offset))
        createData(data_address, data_struct)

    except:
        logger.error("Can't create data struct at {:#010x} with type {}".format(data_address.getOffset(), data_struct))
        return


def fix_cl_buff_chain(cl_buff_addr, vx_version=5):
    if vx_version == 5:
        if cl_buff_addr.offset == 0:
            return

        next_cl_buff_addr = cl_buff_addr
        while True:
            if is_address_in_current_program(next_cl_buff_addr):
                create_struct(next_cl_buff_addr, vx_5_cl_buff)
            else:
                return

            next_cl_buff_addr = toAddr(getInt(next_cl_buff_addr))
            if next_cl_buff_addr == cl_buff_addr:
                return


def fix_clpool(clpool_addr, vx_version=5):
    if vx_version == 5:
        if clpool_addr.offset == 0:
            return

        if is_address_in_current_program(clpool_addr):
            create_struct(clpool_addr, vx_5_clPool)
            cl_head_addr = toAddr(getInt(clpool_addr.add(0x14)))
            fix_cl_buff_chain(cl_head_addr)


def fix_pool_func_tbl(pool_func_addr, vx_version=5):
    if vx_version == 5:
        if pool_func_addr.offset == 0:
            return

        if is_address_in_current_program(pool_func_addr):
            create_struct(pool_func_addr, vx_5_pool_func_tbl)

        func_offset = 0
        for func_name in vx_5_pool_func_dict:
            func_addr = toAddr(getInt(pool_func_addr.add(func_offset)))
            if is_address_in_current_program(func_addr):
                logger.debug("Create function {} at {:#010x}".format(func_name, func_addr.getOffset()))
                disassemble(func_addr)
                function = createFunction(func_addr, func_name)
                if function:
                    function.setName(func_name, SourceType.USER_DEFINED)

                else:
                    # Add original symbol name
                    createLabel(func_addr, func_name, True)

            func_offset += 0x04


def fix_netpool(netpool_addr, vx_version=5):
    if vx_version == 5:
        create_struct(netpool_addr, vx_5_net_pool)
        pool_table_addr = netpool_addr.add(0x24)
        logger.info("Found ClPool table at {:#010x}".format(pool_table_addr.getOffset()))
        pool_status_ptr = netpool_addr.add(0x50)
        logger.info("Found PoolStat at {:#010x}".format(pool_status_ptr.getOffset()))
        pool_function_tbl_prt = netpool_addr.add(0x54)
        logger.info("Found pFuncTbl at {:#010x}".format(pool_function_tbl_prt.getOffset()))

        for i in range(VX_5_CL_TBL_SIZE):
            offset = i * 0x04
            cl_pool_addr = toAddr(getInt(pool_table_addr.add(offset)))
            fix_clpool(cl_pool_addr, vx_version)

        create_struct(toAddr(getInt(pool_status_ptr)), vx_5_pool_stat)
        fix_pool_func_tbl(toAddr(getInt(pool_function_tbl_prt)), vx_version)
