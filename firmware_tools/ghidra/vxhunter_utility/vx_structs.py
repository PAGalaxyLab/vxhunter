# coding=utf-8
from ghidra.program.model.data import (
    CharDataType,
    UnsignedIntegerDataType,
    UnsignedInteger16DataType,
    IntegerDataType,
    Integer16DataType,
    UnsignedLongDataType,
    ShortDataType,
    PointerDataType,
    VoidDataType,
    ByteDataType,
    ArrayDataType,
    StructureDataType,
    EnumDataType
)


# Init data type
ptr_data_type = PointerDataType()
byte_data_type = ByteDataType()
char_data_type = CharDataType()
void_data_type = VoidDataType()
unsigned_int_type = UnsignedIntegerDataType()
unsigned_int16_type = UnsignedInteger16DataType()
int_type = IntegerDataType()
int16_type = Integer16DataType()
unsigned_long_type = UnsignedLongDataType()
short_data_type = ShortDataType()
char_ptr_type = ptr_data_type.getPointer(char_data_type, 4)
void_ptr_type = ptr_data_type.getPointer(void_data_type, 4)


#######################
# VxWorks 5.x Structs #
#######################
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

vx_5_sym_enum = EnumDataType("Vx5symType", 1)
for flag in vx_5_symbol_type_enum:
    vx_5_sym_enum.add(vx_5_symbol_type_enum[flag], flag)

vx_5_symtbl_dt = StructureDataType("VX_5_SYMBOL_IN_TBL", 0x10)
vx_5_symtbl_dt.replaceAtOffset(0, unsigned_int_type, 4, "symHashNode", "")
vx_5_symtbl_dt.replaceAtOffset(4, char_ptr_type, 4, "symNamePtr", "")
vx_5_symtbl_dt.replaceAtOffset(8, void_ptr_type, 4, "symPrt", "")
vx_5_symtbl_dt.replaceAtOffset(0x0c, short_data_type, 4, "symGroup", "")
vx_5_symtbl_dt.replaceAtOffset(0x0e, vx_5_sym_enum, 1, "symType", "")
vx_5_symtbl_dt.replaceAtOffset(0x0f, byte_data_type, 1, "End", "")


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


# typedef struct clPool
#     {
#     int			clSize;		/* cluster size */
#     int			clLg2;		/* cluster log 2 size */
#     int			clNum; 		/* number of clusters */
#     int			clNumFree; 	/* number of clusters free */
#     int			clUsage;	/* number of times used */
#     CL_BUF_ID		pClHead;	/* pointer to the cluster head */
#     struct netPool *	pNetPool;	/* pointer to the netPool */
#     } CL_POOL;
#
# typedef CL_POOL * CL_POOL_ID;
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

# struct	poolFunc			/* POOL_FUNC */
#     {
#     /* pointer to the pool initialization routine */
#     STATUS	(*pInitRtn) (NET_POOL_ID pNetPool, M_CL_CONFIG * pMclBlkConfig, CL_DESC * pClDescTbl,
#                          int clDescTblNumEnt, BOOL fromKheap);
#
#     /* pointer to mBlk free routine */
#     void	(*pMblkFreeRtn) (NET_POOL_ID pNetPool, M_BLK_ID pMblk);
#
#     /* pointer to cluster Blk free routine */
#     void	(*pClBlkFreeRtn) (CL_BLK_ID pClBlk);
#
#     /* pointer to cluster free routine */
#     void	(*pClFreeRtn) (NET_POOL_ID pNetPool, char * pClBuf);
#
#     /* pointer to mBlk/cluster pair free routine */
#     M_BLK_ID 	(*pMblkClFreeRtn) (NET_POOL_ID pNetPool, M_BLK_ID pMblk);
#
#     /* pointer to mBlk get routine */
#     M_BLK_ID	(*pMblkGetRtn) (NET_POOL_ID pNetPool, int canWait, UCHAR type);
#
#     /* pointer to cluster Blk get routine */
#     CL_BLK_ID	(*pClBlkGetRtn) (NET_POOL_ID pNetPool, int canWait);
#
#     /* pointer to a cluster buffer get routine */
#     char *	(*pClGetRtn) (NET_POOL_ID pNetPool, CL_POOL_ID pClPool);
#
#     /* pointer to mBlk/cluster pair get routine */
#     STATUS	(*pMblkClGetRtn) (NET_POOL_ID pNetPool, M_BLK_ID pMblk, int bufSize, int canWait, BOOL bestFit);
#
#     /* pointer to cluster pool Id get routine */
#     CL_POOL_ID	(*pClPoolIdGetRtn) (NET_POOL_ID pNetPool, int	bufSize, BOOL bestFit);
#     };
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
vx_5_net_pool = StructureDataType("VX_5_netPool", 0x58)
vx_5_net_pool.replaceAtOffset(0x00, void_ptr_type, 4, "pmBlkHead", "head of mBlks")
vx_5_net_pool.replaceAtOffset(0x04, void_ptr_type, 4, "pClBlkHead", "head of cluster Blocks")
vx_5_net_pool.replaceAtOffset(0x08, int_type, 4, "mBlkCnt", "number of mblks")
vx_5_net_pool.replaceAtOffset(0x0c, int_type, 4, "mBlkFree", "number of free mblks")
vx_5_net_pool.replaceAtOffset(0x10, int_type, 4, "clMask", "ncluster availability mask")
vx_5_net_pool.replaceAtOffset(0x14, int_type, 4, "clLg2Max", "cluster log2 maximum size")
vx_5_net_pool.replaceAtOffset(0x18, int_type, 4, "clSizeMax", "maximum cluster size")
vx_5_net_pool.replaceAtOffset(0x1c, int_type, 4, "clLg2Min", "cluster log2 minimum size")
vx_5_net_pool.replaceAtOffset(0x20, int_type, 4, "clSizeMin", "minimum cluster size")
vx_5_net_pool.replaceAtOffset(0x24, vx_5_clTbl_array_data_type, vx_5_clTbl_array_data_type.getLength(),
                             "clTbl", "pool table")
vx_5_net_pool.replaceAtOffset(0x50, void_ptr_type, 4, "pPoolStat", "pool statistics")
vx_5_net_pool.replaceAtOffset(0x54, void_ptr_type, 4, "pFuncTbl", "ptr to function ptr table")


vx_5_cl_buff = StructureDataType("VX_5_clBuff", 0x04)
vx_5_cl_buff.replaceAtOffset(0x00, void_ptr_type, 4, "clBuff", "pointer to the next clBuff")

# typedef struct		/* Q_NODE */
#     {
#     UINT     qPriv1;			/* use is queue type dependent */
#     UINT     qPriv2;			/* use is queue type dependent */
#     UINT     qPriv3;			/* use is queue type dependent */
#     UINT     qPriv4;			/* use is queue type dependent */
#     } Q_NODE;
vx_5_q_node = StructureDataType("VX_5_Q_NODE", 0x10)
vx_5_q_node.replaceAtOffset(0x00, unsigned_int_type, 4, "qPriv1", "use is queue type dependent")
vx_5_q_node.replaceAtOffset(0x04, unsigned_int_type, 4, "qPriv2", "use is queue type dependent")
vx_5_q_node.replaceAtOffset(0x08, unsigned_int_type, 4, "qPriv3", "use is queue type dependent")
vx_5_q_node.replaceAtOffset(0x0c, unsigned_int_type, 4, "qPriv4", "use is queue type dependent")

# typedef struct obj_core		/* OBJ_CORE */
#     {
#     struct obj_class *pObjClass;	/* pointer to object's class */
#     } OBJ_CORE;
vx_5_obj_core = StructureDataType("VX_5_OBJ_CORE", 0x04)
vx_5_obj_core.replaceAtOffset(0x00, void_ptr_type, 4, "pObjClass", "pointer to object's class")

# typedef struct		/* Q_HEAD */
#     {
#     Q_NODE  *pFirstNode;		/* first node in queue based on key */
#     UINT     qPriv1;			/* use is queue type dependent */
#     UINT     qPriv2;			/* use is queue type dependent */
#     Q_CLASS *pQClass;			/* pointer to queue class */
#     } Q_HEAD;
vx_5_q_head = StructureDataType("VX_5_Q_HEAD", 0x10)
vx_5_q_head.replaceAtOffset(0x00, void_ptr_type, 4, "*pFirstNode", "pointer to first node in queue based on key")
vx_5_q_head.replaceAtOffset(0x04, unsigned_int_type, 4, "qPriv1", "use is queue type dependent")
vx_5_q_head.replaceAtOffset(0x08, unsigned_int_type, 4, "qPriv2", "use is queue type dependent")
vx_5_q_head.replaceAtOffset(0x0c, void_ptr_type, 4, "*pQClass", "pointer to queue class")

# typedef struct eventsCb
#     {
#     UINT32 wanted;	/* 0x00: events wanted				*/
#     volatile UINT32 received;	/* 0x04: all events received		*/
#     UINT8  options;	/* 0x08: user options				*/
#     UINT8  sysflags;	/* 0x09: flags used by internal code only	*/
#     UINT8  pad[2];	/* 0x0a: alignment on 32bit, possible extension	*/
#     } EVENTS;		/* 0x0c: total size				*/
vx_5_events_cb_pad_type = ArrayDataType(byte_data_type, 2, byte_data_type.getLength())
vx_5_events_cb = StructureDataType("VX_5_eventsCb", 0x0c)
vx_5_events_cb.replaceAtOffset(0x00, unsigned_int_type, 4, "wanted", "0x00: events wanted")
vx_5_events_cb.replaceAtOffset(0x04, unsigned_int_type, 4, "received", "0x04: all events received")
vx_5_events_cb.replaceAtOffset(0x08, byte_data_type, 1, "options", "0x08: user options")
vx_5_events_cb.replaceAtOffset(0x09, byte_data_type, 1, "sysflags", "0x09: flags used by internal code only")
vx_5_events_cb.replaceAtOffset(0x0a, vx_5_events_cb_pad_type, vx_5_events_cb_pad_type.getLength(),
                               "qPriv2", "0x0a: alignment on 32bit, possible extension")


# typedef struct windTcb		/* WIND_TCB - task control block */
#     {
#     Q_NODE		qNode;		/* 0x00: multiway q node: rdy/pend q */
#     Q_NODE		tickNode;	/* 0x10: multiway q node: tick q */
#     Q_NODE		activeNode;	/* 0x20: multiway q node: active q */
#
#     OBJ_CORE		objCore;	/* 0x30: object management */
#     char *		name;		/* 0x34: pointer to task name */
#     int			options;	/* 0x38: task option bits */
#     UINT		status;		/* 0x3c: status of task */
#     UINT		priority;	/* 0x40: task's current priority */
#     UINT		priNormal;	/* 0x44: task's normal priority */
#     UINT		priMutexCnt;	/* 0x48: nested priority mutex owned */
#     struct semaphore *	pPriMutex;	/* 0x4c: pointer to inheritance mutex */
#
#     UINT		lockCnt;	/* 0x50: preemption lock count */
#     UINT		tslice;		/* 0x54: current count of time slice */
#
#     UINT16		swapInMask;	/* 0x58: task's switch in hooks */
#     UINT16		swapOutMask;	/* 0x5a: task's switch out hooks */
#
#     Q_HEAD *		pPendQ;		/* 0x5c: q head pended on (if any) */
#
#     UINT		safeCnt;	/* 0x60: safe-from-delete count */
#     Q_HEAD		safetyQHead;	/* 0x64: safe-from-delete q head */
#
#     FUNCPTR		entry;		/* 0x74: entry point of task */
#
#     char *		pStackBase;	/* 0x78: points to bottom of stack */
#     char *		pStackLimit;	/* 0x7c: points to stack limit */
#     char *		pStackEnd;	/* 0x80: points to init stack limit */
#
#     int			errorStatus;	/* 0x84: most recent task error */
#     int			exitCode;	/* 0x88: error passed to exit () */
#
#     struct sigtcb *	pSignalInfo;	/* 0x8c: ptr to signal info for task */
#     struct selContext *	pSelectContext;	/* 0x90: ptr to select info for task */
#
#     UINT		taskTicks;	/* 0x94: total number of ticks */
#     UINT		taskIncTicks;	/* 0x98: number of ticks in slice */
#
#     struct taskVar *	pTaskVar;	/* 0x9c: ptr to task variable list */
#     struct rpcModList *	pRPCModList;	/* 0xa0: ptr to rpc module statics */
#     struct fpContext *	pFpContext;	/* 0xa4: fpoint coprocessor context */
#
#     struct __sFILE *	taskStdFp[3];	/* 0xa8: stdin,stdout,stderr fps */
#     int			taskStd[3];	/* 0xb4: stdin,stdout,stderr fds */
#
#     char **		ppEnviron;	/* 0xc0: environment var table */
#     int                 envTblSize;     /* 0xc4: number of slots in table */
#     int                 nEnvVarEntries; /* 0xc8: num env vars used */
#     struct sm_obj_tcb *	pSmObjTcb;	/* 0xcc: shared mem object TCB */
#     int			windxLock;	/* 0xd0: lock for windX */
#     void *		pComLocal;	/* 0xd4: COM task-local storage ptr */
#     REG_SET *		pExcRegSet;	/* 0xd8: exception regSet ptr or NULL */
#     EVENTS		events;		/* 0xdc: event info for the task */
#     WDB_INFO *		pWdbInfo;	/* 0xe8: ptr to WDB info - future use */
#     void *		pPthread;	/* 0xec: ptr to pthread data structs */
#     int			reserved1;	/* 0xf0: possible WRS extension */
#     int			reserved2;	/* 0xf4: possible WRS extension */
#     int			spare1;		/* 0xf8: possible user extension */
#     int			spare2;		/* 0xfc: possible user extension */
#     int			spare3;		/* 0x100: possible user extension */
#     int			spare4;		/* 0x104: possible user extension */
vx_5_taskStdFp_array_data_type = ArrayDataType(void_ptr_type, 3, void_ptr_type.getLength())
vx_5_taskStd_array_data_type = ArrayDataType(void_ptr_type, 3, void_ptr_type.getLength())
vx_5_wind_tcb = StructureDataType("VX_5_windTcb", 0x108)
vx_5_wind_tcb.replaceAtOffset(0x00, vx_5_q_node, vx_5_q_node.getLength(), "qNode", "0x00: multiway q node: rdy/pend q")
vx_5_wind_tcb.replaceAtOffset(0x10, vx_5_q_node, vx_5_q_node.getLength(), "tickNode", "0x10: multiway q node: tick q")
vx_5_wind_tcb.replaceAtOffset(0x20, vx_5_q_node, vx_5_q_node.getLength(), "activeNode", "0x20: multiway q node: active q")
vx_5_wind_tcb.replaceAtOffset(0x30, vx_5_obj_core, vx_5_obj_core.getLength(), "objCore", "0x30: object management")
vx_5_wind_tcb.replaceAtOffset(0x34, void_ptr_type, 4, "name", "0x34: pointer to task name")
vx_5_wind_tcb.replaceAtOffset(0x34, int_type, 4, "options", "0x38: task option bits")
vx_5_wind_tcb.replaceAtOffset(0x3C, unsigned_int_type, 4, "status", "0x3c: status of task")
vx_5_wind_tcb.replaceAtOffset(0x40, unsigned_int_type, 4, "priority", "0x40: task's current priority")
vx_5_wind_tcb.replaceAtOffset(0x44, unsigned_int_type, 4, "priNormal", "0x44: task's normal priority")
vx_5_wind_tcb.replaceAtOffset(0x48, unsigned_int_type, 4, "priMutexCnt", "0x48: nested priority mutex owned")
vx_5_wind_tcb.replaceAtOffset(0x4C, void_ptr_type, 4, "pPriMutex", "0x4c: pointer to inheritance mutex")
vx_5_wind_tcb.replaceAtOffset(0x50, unsigned_int_type, 4, "lockCnt", "0x50: preemption lock count")
vx_5_wind_tcb.replaceAtOffset(0x54, unsigned_int_type, 4, "tslice", "0x54: current count of time slice")
vx_5_wind_tcb.replaceAtOffset(0x58, unsigned_int16_type, 2, "swapInMask", "0x58: task's switch in hooks")
vx_5_wind_tcb.replaceAtOffset(0x5a, unsigned_int16_type, 2, "swapOutMask", "0x5a: task's switch out hooks")
vx_5_wind_tcb.replaceAtOffset(0x5c, void_ptr_type, 4, "pPendQ", "0x5c: q head pended on (if any)")
vx_5_wind_tcb.replaceAtOffset(0x60, unsigned_int_type, 4, "safeCnt", "0x60: safe-from-delete count")
vx_5_wind_tcb.replaceAtOffset(0x64, vx_5_q_head, vx_5_q_head.getLength(), "safetyQHead", "0x64: safe-from-delete q head")
vx_5_wind_tcb.replaceAtOffset(0x74, void_ptr_type, 4, "entry", "0x74: entry point of task")
vx_5_wind_tcb.replaceAtOffset(0x78, void_ptr_type, 4, "pStackBase", "0x78: points to bottom of stack")
vx_5_wind_tcb.replaceAtOffset(0x7c, void_ptr_type, 4, "pStackLimit", "0x7c: points to stack limit")
vx_5_wind_tcb.replaceAtOffset(0x80, void_ptr_type, 4, "pStackEnd", "0x80: points to init stack limit")
vx_5_wind_tcb.replaceAtOffset(0x84, int_type, 4, "errorStatus", "0x84: most recent task error")
vx_5_wind_tcb.replaceAtOffset(0x88, int_type, 4, "exitCode", "0x88: error passed to exit ()")
vx_5_wind_tcb.replaceAtOffset(0x8c, void_ptr_type, 4, "pSignalInfo", "0x8c: ptr to signal info for task")
vx_5_wind_tcb.replaceAtOffset(0x90, void_ptr_type, 4, "pSelectContext", "0x90: ptr to select info for task")
vx_5_wind_tcb.replaceAtOffset(0x94, unsigned_int_type, 4, "taskTicks", "0x94: total number of ticks")
vx_5_wind_tcb.replaceAtOffset(0x98, unsigned_int_type, 4, "taskIncTicks", "0x98: number of ticks in slice")
vx_5_wind_tcb.replaceAtOffset(0x9c, void_ptr_type, 4, "pTaskVar", "0x9c: ptr to task variable list")
vx_5_wind_tcb.replaceAtOffset(0xa0, void_ptr_type, 4, "pRPCModList", "0xa0: ptr to rpc module statics")
vx_5_wind_tcb.replaceAtOffset(0xa4, void_ptr_type, 4, "pFpContext", "0xa4: fpoint coprocessor context")
vx_5_wind_tcb.replaceAtOffset(0xa8, vx_5_taskStdFp_array_data_type, vx_5_taskStdFp_array_data_type.getLength(),
                              "taskStdFp", "0xa8: stdin,stdout,stderr fps")
vx_5_wind_tcb.replaceAtOffset(0xb4, vx_5_taskStd_array_data_type, vx_5_taskStd_array_data_type.getLength(),
                              "taskStd", "0xb4: stdin,stdout,stderr fds")
vx_5_wind_tcb.replaceAtOffset(0xc0, void_ptr_type, 4, "ppEnviron", "0xc0: environment var table")
vx_5_wind_tcb.replaceAtOffset(0xc4, int_type, 4, "envTblSize", "0xc4: number of slots in table")
vx_5_wind_tcb.replaceAtOffset(0xc8, int_type, 4, "nEnvVarEntries", "0xc8: num env vars used")
vx_5_wind_tcb.replaceAtOffset(0xcc, void_ptr_type, 4, "pSmObjTcb", "0xcc: shared mem object TCB")
vx_5_wind_tcb.replaceAtOffset(0xd0, int_type, 4, "windxLock", "0xd0: lock for windX")
vx_5_wind_tcb.replaceAtOffset(0xd4, void_ptr_type, 4, "pComLocal", "0xd4: COM task-local storage ptr")
vx_5_wind_tcb.replaceAtOffset(0xd8, void_ptr_type, 4, "pExcRegSet", "0xd8: exception regSet ptr or NULL")
vx_5_wind_tcb.replaceAtOffset(0xdc, vx_5_events_cb, vx_5_events_cb.getLength(), "events", "0xcc: shared mem object TCB")
vx_5_wind_tcb.replaceAtOffset(0xe8, void_ptr_type, 4, "pWdbInfo", "0xe8: ptr to WDB info - future use")
vx_5_wind_tcb.replaceAtOffset(0xec, void_ptr_type, 4, "pPthread", "0xec: ptr to pthread data structs")
vx_5_wind_tcb.replaceAtOffset(0xf0, int_type, 4, "reserved1", "0xf0: possible WRS extension")
vx_5_wind_tcb.replaceAtOffset(0xf4, int_type, 4, "reserved2", "0xf4: possible WRS extension")
vx_5_wind_tcb.replaceAtOffset(0xf8, int_type, 4, "spare1", "0xf8: possible user extension")
vx_5_wind_tcb.replaceAtOffset(0xfc, int_type, 4, "spare2", "0xfc: possible user extension")
vx_5_wind_tcb.replaceAtOffset(0x100, int_type, 4, "spare3", "0x100: possible user extension")
vx_5_wind_tcb.replaceAtOffset(0x104, int_type, 4, "spare4", "0x104: possible user extension")


#######################
# VxWorks 6.x Structs #
#######################
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

vx_6_sym_enum = EnumDataType("Vx6symType", 1)
for flag in vx_6_symbol_type_enum:
    vx_6_sym_enum.add(vx_6_symbol_type_enum[flag], flag)


vx_6_symtbl_dt = StructureDataType("VX_6_SYMBOL_IN_TBL", 0x14)
vx_6_symtbl_dt.replaceAtOffset(0, unsigned_int_type, 4, "symHashNode", "")
vx_6_symtbl_dt.replaceAtOffset(4, char_ptr_type, 4, "symNamePtr", "")
vx_6_symtbl_dt.replaceAtOffset(8, void_ptr_type, 4, "symPrt", "")
vx_6_symtbl_dt.replaceAtOffset(0x0c, unsigned_int_type, 4, "symRef", "moduleId of module, or predefined SYMREF")
vx_6_symtbl_dt.replaceAtOffset(0x10, short_data_type, 4, "symGroup", "")
vx_6_symtbl_dt.replaceAtOffset(0x12, vx_6_sym_enum, 1, "symType", "")
vx_6_symtbl_dt.replaceAtOffset(0x13, byte_data_type, 1, "End", "")
