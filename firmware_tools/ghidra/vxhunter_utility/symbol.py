# coding=utf-8
from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.program.model.data import (
    CharDataType,
    UnsignedIntegerDataType,
    IntegerDataType,
    UnsignedLongDataType,
    ShortDataType,
    PointerDataType,
    VoidDataType,
    ByteDataType,
    ArrayDataType,
    StructureDataType,
    EnumDataType
)
from ghidra.program.model.symbol import RefType, SourceType
from common import *
import string


# The Python module that Ghidra directly launches is always called __main__.  If we import
# everything from that module, this module will behave as if Ghidra directly launched it.
from __main__ import *


function_name_key_words = ['bzero', 'usrInit', 'bfill']

need_create_function = [
    0x04,
    0x05
]

# tp_link_symbol_map = ['']

vx_5_symbol_type_enum = {
    0x00: "Undefined Symbol",
    0x01: "Global (external)",
    0x02: "Local Absolute",
    0x03: "Global Absolute",
    0x04: "Local .text",
    0x05: "Global .text",
    0x06: "Local Data",
    0x07: "Global Data",
    0x08: "Local BSS",
    0x09: "Global BSS",
    0x12: "Local Common symbol",
    0x13: "Global Common symbol",
    0x40: "Local Symbols related to a PowerPC SDA section",
    0x41: "Global Symbols related to a PowerPC SDA section",
    0x80: "Local symbols related to a PowerPC SDA2 section",
    0x81: "Global symbols related to a PowerPC SDA2 section"
}

vx_6_symbol_type_enum = {
    0x00: "Undefined Symbol",
    0x01: "Global (external)",
    0x02: "Local Absolute",
    0x03: "Global Absolute",
    0x04: "Local .text",
    0x05: "Global .text",
    0x08: "Local Data",
    0x09: "Global Data",
    0x10: "Local BSS",
    0x11: "Global BSS",
    0x20: "Local Common symbol",
    0x21: "Global Common symbol",
    0x40: "Local Symbols",
    0x41: "Global Symbols"
}

# Init data type
ptr_data_type = PointerDataType()
byte_data_type = ByteDataType()
char_data_type = CharDataType()
void_data_type = VoidDataType()
unsigned_int_type = UnsignedIntegerDataType()
int_type = IntegerDataType()
unsigned_long_type = UnsignedLongDataType()
short_data_type = ShortDataType()
char_ptr_type = ptr_data_type.getPointer(char_data_type, 4)
void_ptr_type = ptr_data_type.getPointer(void_data_type, 4)
# Prepare VxWorks symbol types
vx_5_sym_enum = EnumDataType("Vx5symType", 1)
for flag in vx_5_symbol_type_enum:
    vx_5_sym_enum.add(vx_5_symbol_type_enum[flag], flag)
vx_6_sym_enum = EnumDataType("Vx6symType", 1)
for flag in vx_6_symbol_type_enum:
    vx_6_sym_enum.add(vx_6_symbol_type_enum[flag], flag)

vx_5_symtbl_dt = StructureDataType("VX_5_SYMBOL_IN_TBL", 0x10)
vx_5_symtbl_dt.replaceAtOffset(0, unsigned_int_type, 4, "symHashNode", "")
vx_5_symtbl_dt.replaceAtOffset(4, char_ptr_type, 4, "symNamePtr", "")
vx_5_symtbl_dt.replaceAtOffset(8, void_ptr_type, 4, "symPrt", "")
vx_5_symtbl_dt.replaceAtOffset(0x0c, short_data_type, 4, "symGroup", "")
vx_5_symtbl_dt.replaceAtOffset(0x0e, vx_5_sym_enum, 1, "symType", "")
vx_5_symtbl_dt.replaceAtOffset(0x0f, byte_data_type, 1, "End", "")

vx_6_symtbl_dt = StructureDataType("VX_6_SYMBOL_IN_TBL", 0x14)
vx_6_symtbl_dt.replaceAtOffset(0, unsigned_int_type, 4, "symHashNode", "")
vx_6_symtbl_dt.replaceAtOffset(4, char_ptr_type, 4, "symNamePtr", "")
vx_6_symtbl_dt.replaceAtOffset(8, void_ptr_type, 4, "symPrt", "")
vx_6_symtbl_dt.replaceAtOffset(0x0c, unsigned_int_type, 4, "symRef", "moduleId of module, or predefined SYMREF")
vx_6_symtbl_dt.replaceAtOffset(0x10, short_data_type, 4, "symGroup", "")
vx_6_symtbl_dt.replaceAtOffset(0x12, vx_6_sym_enum, 1, "symType", "")
vx_6_symtbl_dt.replaceAtOffset(0x13, byte_data_type, 1, "End", "")

vx_5_sys_symtab = StructureDataType("VX_5_SYSTEM_SYMBOL_TABLE", 0x3C)
vx_5_sys_symtab.replaceAtOffset(0x00, void_ptr_type, 4, "objCore", "Pointer to object's class")
vx_5_sys_symtab.replaceAtOffset(0x04, void_ptr_type, 4, "nameHashId", "Pointer to HASH_TBL")
vx_5_sys_symtab.replaceAtOffset(0x08, char_data_type, 0x28, "symMutex", "symbol table mutual exclusion sem")
vx_5_sys_symtab.replaceAtOffset(0x30, void_ptr_type, 4, "symPartId", "memory partition id for symbols")
vx_5_sys_symtab.replaceAtOffset(0x34, unsigned_int_type, 4, "sameNameOk", "symbol table name clash policy")
vx_5_sys_symtab.replaceAtOffset(0x38, unsigned_int_type, 4, "PART_ID", "current number of symbols in table")


vx_5_hash_tbl = StructureDataType("VX_5_HASH_TABLE", 0x18)
vx_5_hash_tbl.replaceAtOffset(0x00, void_ptr_type, 4, "objCore", "Pointer to object's class")
vx_5_hash_tbl.replaceAtOffset(0x04, unsigned_int_type, 4, "elements", "Number of elements in table")
vx_5_hash_tbl.replaceAtOffset(0x08, void_ptr_type, 4, "keyCmpRtn", "Comparator function")
vx_5_hash_tbl.replaceAtOffset(0x0c, void_ptr_type, 4, "keyRtn", "Pointer to object's class")
vx_5_hash_tbl.replaceAtOffset(0x10, unsigned_int_type, 4, "keyArg", "Hash function argument")
vx_5_hash_tbl.replaceAtOffset(0x14, void_ptr_type, 4, "*pHashTbl", "Pointer to hash table array")

vx_5_sl_list = StructureDataType("VX_5_HASH_TABLE_LIST", 0x08)
vx_5_sl_list.replaceAtOffset(0x00, void_ptr_type, 4, "head", "header of list")
vx_5_sl_list.replaceAtOffset(0x04, void_ptr_type, 4, "tail", "tail of list")

'''
typedef struct clPool
    {
    int			clSize;		/* cluster size */
    int			clLg2;		/* cluster log 2 size */
    int			clNum; 		/* number of clusters */
    int			clNumFree; 	/* number of clusters free */
    int			clUsage;	/* number of times used */
    CL_BUF_ID		pClHead;	/* pointer to the cluster head */
    struct netPool *	pNetPool;	/* pointer to the netPool */
    } CL_POOL; 

typedef CL_POOL * CL_POOL_ID; 
'''
vx_5_clPool = StructureDataType("VX_5_clPool", 0x1c)
vx_5_clPool.replaceAtOffset(0x00, int_type, 4, "clSize", "cluster size")
vx_5_clPool.replaceAtOffset(0x04, int_type, 4, "clLg2", "cluster log 2 size")
vx_5_clPool.replaceAtOffset(0x08, int_type, 4, "clNum", "number of clusters")
vx_5_clPool.replaceAtOffset(0x0c, int_type, 4, "clNumFree", "number of clusters free")
vx_5_clPool.replaceAtOffset(0x10, int_type, 4, "clUsage", "number of times used")
vx_5_clPool.replaceAtOffset(0x14, void_ptr_type, 4, "pClHead", "pointer to the cluster head")
vx_5_clPool.replaceAtOffset(0x18, void_ptr_type, 4, "pNetPool", "pointer to the netPool")

'''
typedef struct mbstat
    {
    ULONG	mNum;			/* mBlks obtained from page pool */
    ULONG	mDrops;			/* times failed to find space */
    ULONG	mWait;			/* times waited for space */
    ULONG	mDrain;			/* times drained protocols for space */
    ULONG	mTypes[256];		/* type specific mBlk allocations */
    } M_STAT;
'''
VX_5_M_TYPES_SIZE = 256
vx_5_mTypes_array_data_type = ArrayDataType(unsigned_long_type, VX_5_M_TYPES_SIZE, unsigned_long_type.getLength())
vx_5_pool_stat = StructureDataType("VX_5_PoolStat", 0x10 + VX_5_M_TYPES_SIZE * 4)
vx_5_pool_stat.replaceAtOffset(0x00, unsigned_long_type, 4, "mNum", "mBlks obtained from page pool")
vx_5_pool_stat.replaceAtOffset(0x04, int_type, 4, "mDrops", "times failed to find space")
vx_5_pool_stat.replaceAtOffset(0x08, int_type, 4, "mWait", "times waited for space")
vx_5_pool_stat.replaceAtOffset(0x0c, int_type, 4, "mDrain", "times drained protocols for space")
vx_5_pool_stat.replaceAtOffset(0x10, vx_5_mTypes_array_data_type, vx_5_mTypes_array_data_type.getLength(),
                               "mTypes", "type specific mBlk allocations")


'''
struct	poolFunc			/* POOL_FUNC */
    {
    /* pointer to the pool initialization routine */
    STATUS	(*pInitRtn) (NET_POOL_ID pNetPool, M_CL_CONFIG * pMclBlkConfig, CL_DESC * pClDescTbl, 
                         int clDescTblNumEnt, BOOL fromKheap);

    /* pointer to mBlk free routine */
    void	(*pMblkFreeRtn) (NET_POOL_ID pNetPool, M_BLK_ID pMblk);

    /* pointer to cluster Blk free routine */
    void	(*pClBlkFreeRtn) (CL_BLK_ID pClBlk);

    /* pointer to cluster free routine */
    void	(*pClFreeRtn) (NET_POOL_ID pNetPool, char * pClBuf);

    /* pointer to mBlk/cluster pair free routine */
    M_BLK_ID 	(*pMblkClFreeRtn) (NET_POOL_ID pNetPool, M_BLK_ID pMblk);

    /* pointer to mBlk get routine */
    M_BLK_ID	(*pMblkGetRtn) (NET_POOL_ID pNetPool, int canWait, UCHAR type);

    /* pointer to cluster Blk get routine */
    CL_BLK_ID	(*pClBlkGetRtn) (NET_POOL_ID pNetPool, int canWait);
    
    /* pointer to a cluster buffer get routine */
    char *	(*pClGetRtn) (NET_POOL_ID pNetPool, CL_POOL_ID pClPool);

    /* pointer to mBlk/cluster pair get routine */
    STATUS	(*pMblkClGetRtn) (NET_POOL_ID pNetPool, M_BLK_ID pMblk, int bufSize, int canWait, BOOL bestFit);

    /* pointer to cluster pool Id get routine */
    CL_POOL_ID	(*pClPoolIdGetRtn) (NET_POOL_ID pNetPool, int	bufSize, BOOL bestFit);
    };
'''
vx_5_pool_func_dict = {
    "pInitRtn": "pointer to the pool initialization routine",
    "pMblkFreeRtn": "pointer to mBlk free routine",
    "pClBlkFreeRtn": "pointer to cluster Blk free routine",
    "pClFreeRtn": "pointer to cluster free routine",
    "pMblkClFreeRtn": "pointer to mBlk/cluster pair free routine",
    "pMblkGetRtn": "pointer to mBlk get routine",
    "pClBlkGetRtn": "pointer to cluster Blk get routine",
    "pClGetRtn": "pointer to a cluster buffer get routine",
    "pMblkClGetRtn": "pointer to mBlk/cluster pair get routine",
    "pClPoolIdGetRtn": "pointer to cluster pool Id get routine",
}
vx_5_pool_func_tbl = StructureDataType("VX_5_pFuncTbl", 0x28)
func_offset = 0
for func_name in vx_5_pool_func_dict:
    func_desc = vx_5_pool_func_dict[func_name]
    vx_5_pool_func_tbl.replaceAtOffset(func_offset, void_ptr_type, 4, "*{}".format(func_name), func_desc)
    func_offset += 0x04


'''
struct netPool				/* NET_POOL */
    {
    M_BLK_ID	pmBlkHead;		/* head of mBlks */
    CL_BLK_ID	pClBlkHead;		/* head of cluster Blocks */
    int		mBlkCnt;		/* number of mblks */
    int		mBlkFree;		/* number of free mblks */
    int		clMask;			/* cluster availability mask */
    int		clLg2Max;		/* cluster log2 maximum size */
    int		clSizeMax;		/* maximum cluster size */
    int		clLg2Min;		/* cluster log2 minimum size */
    int		clSizeMin;		/* minimum cluster size */
    CL_POOL * 	clTbl [CL_TBL_SIZE];	/* pool table */
    M_STAT *	pPoolStat;		/* pool statistics */
    POOL_FUNC *	pFuncTbl;		/* ptr to function ptr table */
    };
'''
VX_5_CL_TBL_SIZE = 11
vx_5_clTbl_array_data_type = ArrayDataType(void_ptr_type, VX_5_CL_TBL_SIZE, void_ptr_type.getLength())
vx_5_netPool = StructureDataType("VX_5_netPool", 0x58)
vx_5_netPool.replaceAtOffset(0x00, void_ptr_type, 4, "pmBlkHead", "head of mBlks")
vx_5_netPool.replaceAtOffset(0x04, void_ptr_type, 4, "pClBlkHead", "head of cluster Blocks")
vx_5_netPool.replaceAtOffset(0x08, int_type, 4, "mBlkCnt", "number of mblks")
vx_5_netPool.replaceAtOffset(0x0C, int_type, 4, "mBlkFree", "number of free mblks")
vx_5_netPool.replaceAtOffset(0x10, int_type, 4, "clMask", "ncluster availability mask")
vx_5_netPool.replaceAtOffset(0x14, int_type, 4, "clLg2Max", "cluster log2 maximum size")
vx_5_netPool.replaceAtOffset(0x18, int_type, 4, "clSizeMax", "maximum cluster size")
vx_5_netPool.replaceAtOffset(0x1C, int_type, 4, "clLg2Min", "cluster log2 minimum size")
vx_5_netPool.replaceAtOffset(0x20, int_type, 4, "clSizeMin", "minimum cluster size")
vx_5_netPool.replaceAtOffset(0x24, vx_5_clTbl_array_data_type, vx_5_clTbl_array_data_type.getLength(),
                             "clTbl", "pool table")
vx_5_netPool.replaceAtOffset(0x50, void_ptr_type, 4, "pPoolStat", "pool statistics")
vx_5_netPool.replaceAtOffset(0x54, void_ptr_type, 4, "pFuncTbl", "ptr to function ptr table")


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


def fix_clpool(clpool_addr, vx_version=5):
    if vx_version == 5:
        if clpool_addr.offset == 0:
            return

        if is_address_in_current_program(clpool_addr):
            create_struct(clpool_addr, vx_5_clPool)


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
                print("Create function {} at {:#010x}".format(func_name, func_addr.getOffset()))
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
        create_struct(netpool_addr, vx_5_netPool)
        pool_table_addr = netpool_addr.add(0x24)
        print("Found ClPool table at {:#010x}".format(pool_table_addr.getOffset()))
        pool_status_ptr = netpool_addr.add(0x50)
        print("Found PoolStat at {:#010x}".format(pool_status_ptr.getOffset()))
        pool_function_tbl_prt = netpool_addr.add(0x54)
        print("Found pFuncTbl at {:#010x}".format(pool_function_tbl_prt.getOffset()))

        for i in range(VX_5_CL_TBL_SIZE):
            offset = i * 0x04
            cl_pool_addr = toAddr(getInt(pool_table_addr.add(offset)))
            fix_clpool(cl_pool_addr, vx_version)

        create_struct(toAddr(getInt(pool_status_ptr)), vx_5_pool_stat)
        fix_pool_func_tbl(toAddr(getInt(pool_function_tbl_prt)), vx_version)
