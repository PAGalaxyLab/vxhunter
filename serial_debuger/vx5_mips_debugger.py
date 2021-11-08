# !/usr/bin/env python2
# coding=utf-8
from scapy.packet import *
from scapy.fields import *
from scapy.layers.dns import *
from scapy.layers.inet import TCP, IP, Ether, UDP
from vx_base_debugger import VxSerialBaseDebuger
from keystone import *
from capstone import *
from mips16e_asm import *

MIPS_REGS = [
    '$0', 't0', 's0', 't8',
    'at', 't1', 's1', 't9',
    'v0', 't2', 's2', 'k0',
    'v1', 't3', 's3', 'k1',
    'a0', 't4', 's4', 'gp',
    'a1', 't5', 's5', 'sp',
    'a2', 't6', 's6', 's8',
    'a3', 't7', 's7', 'ra',
    'divlo', 'divhi', 'sr', 'pc',
]

MIPS_REGS_LIST_TO_FIX = {
    'at': 1,
    'v0': 2,
    'v1': 3,
    'a0': 4,
    'a1': 5,
    'a2': 6,
    'a3': 7,
    't0': 8,
    't1': 9,
    't2': 10,
    't3': 11,
    't4': 12,
    't5': 13,
    't6': 14,
    't7': 15,
    's0': 16,
    's1': 17,
    's2': 18,
    's3': 19,
    's4': 20,
    's5': 21,
    's6': 22,
    's7': 23,
    't8': 24,
    't9': 25,
    'k0': 26,
    'k1': 27,
    'gp': 28,
    # 'sp': 29,
    'fp': 30,
    # 'ra': 31,
}

BP_BLACK_LIST = {
    "strlen": [0x80100040, 0x80100058]
}

mBlk_flags = [
    "M_EXT(0x01)",  # has an associated cluster
    "M_PKTHDR(0x02)",  # start of record
    "M_EOR(0x04)",  # end of record
    "M_FORWARD(0x08)",  # packet to be forwarded
    "reserved",
    "reserved",
    "reserved",
    "reserved",
]

mBlk_types = {
    0x00: "MT_FREE(0x00)",  # should be on free list
    0x01: "MT_DATA(0x01)",  # dynamic (data) allocation
    0x02: "MT_HEADER(0x02)",  # packet header
    0x03: "MT_SOCKET(0x03)",  # socket structure
    0x04: "MT_PCB(0x04)",  # protocol control block
    0x05: "MT_RTABLE(0x05)",  # routing tables
    0x06: "MT_HTABLE(0x06)",  # IMP host tables
    0x07: "MT_ATABLE(0x07)",  # address resolution tables
    0x08: "MT_SONAME(0x08)",  # socket name
    0x09: "MT_ZOMBIE(0x09)",  # zombie proc status
    0x0a: "MT_SOOPTS(0x0a)",  # socket options
    0x0b: "MT_FTABLE(0x0b)",  # fragment reassembly header
    0x0c: "MT_RIGHTS(0x0c)",  # access rights
    0x0d: "MT_IFADDR(0x0d)",  # interface address
    0x0e: "MT_CONTROL(0x0e)",  # extra-data protocol message
    0x0f: "MT_OOBDATA(0x0f)",  # expedited data
    0x10: "MT_IPMOPTS(0x10)",  # internet multicast options
    0x11: "MT_IPMADDR(0x11)",  # internet multicast address
    0x12: "MT_IFMADDR(0x12)",  # link-level multicast address
    0x13: "MT_MRTABLE(0x13)",  # multicast routing tables
    0x14: "NUM_MBLK_TYPES(0x14)",  # number of mBlk types defined

}


class mBlkHdr(Packet):
    fields_desc = [
        XIntField("mNext", 0),
        XIntField("mNextPkt", 0),
        XIntField("mData", 0),
        XIntField("mLen", 0),
        BitEnumField("mType", 0, 8, mBlk_types),
        FlagsField("mFlags", 0, 8, mBlk_flags),
        XShortField("reserved", 0),
    ]


bind_layers(mBlkHdr, Padding)


class mBlkPktHdr(Packet):
    fields_desc = [
        XStrFixedLenField("Rawifnet", "", length=0x18),
        XIntField("len", 0),
    ]


bind_layers(mBlkPktHdr, Padding)


class clBlk(Packet):
    fields_desc = [
        XIntField("clNode", 0),  # union of next clBlk, buffer ptr
        XIntField("clSize", 0),
        XIntField("clRefCnt", 0),
        XIntField("pClFreeRtnAddr", 0),
        XIntField("clFreeArg1", 0),
        XIntField("clFreeArg2", 0),
        XIntField("clFreeArg3", 0),
        XIntField("pNetPoolAddr", 0),
    ]


class mBlk(Packet):
    fields_desc = [
        PacketField("mBlkHdr", mBlkHdr(), mBlkHdr),
        PacketField("mBlkPktHdr", mBlkPktHdr(), mBlkPktHdr),
        XIntField("pClBlkAddr", 0),
        XIntField("pNetPoolAddr", 0),
    ]


class clPool(Packet):
    fields_desc = [
        XIntField("ClPoolAddr", 0),
    ]


bind_layers(clPool, Padding)


class PoolStat(Packet):
    fields_desc = [
        XIntField("mNum", 0),
        XIntField("mDrops", 0),
        XIntField("mWait", 0),
        XIntField("mDrain", 0),
    ]


class netPool(Packet):
    fields_desc = [
        XIntField("pmBlkHead", 0),
        XIntField("pClBlkHead", 0),
        XIntField("Unknown0", 0),
        XIntField("mBlkCnt", 0),
        XIntField("mBlkFree", 0),
        XIntField("clMask", 0),
        XIntField("clLg2Max", 0),
        XIntField("clSizeMax", 0),
        XIntField("clLg2Min", 0),
        XIntField("clSizeMin", 0),
        PacketListField("clTbl", [], clPool, count_from=lambda p: 0x0d),
        XIntField("pPoolStat", 0),
        XIntField("pFuncTbl", 0)
    ]


class pFuncTbl(Packet):
    fields_desc = [
        XIntField("_poolInit", 0),
        XIntField("_mBlkFree", 0),
        XIntField("_clBlkFree", 0),
        XIntField("_clFree", 0),
        XIntField("_mBlkClFree", 0),
        XIntField("_mBlkGet", 0),
        XIntField("_clBlkGet", 0),
        XIntField("_clusterGet", 0),
        XIntField("_mClGet", 0),
        XIntField("_clPoolIdGet", 0)
    ]


class DebugStack(Packet):
    fields_desc = [
        XIntField("DbgFlag", 0),
        XIntField("OriginalRA", 0),
        XIntField("BreakPoint", 0),
        XIntField("CacheUpdateAddress", 0),
        XIntField("CacheUpdateSize", 0),
        XIntField("CacheUpdateCount", 0),
    ]


class Vx5MipsDebugger(VxSerialBaseDebuger):

    def text_update(self, update_address, update_size):
        """Update Process cache

        :param update_address: Memory address to update.
        :param update_size: Cache update size
        :return: True if update succeed
        """
        if self.current_bp_info["bp_address"] == 0:
            self.logger.debug("current bp_address is zero, skip text update.")
            return None
        flag_address = self.current_bp_info["flag_address"]
        pack_parm = ">I"
        if self.endian == 2:
            pack_parm = "<I"

        original_update_count = struct.unpack(pack_parm, self.get_mem_dump(flag_address + 0x14, 0x04))[0]
        self.write_memory_data(flag_address + 0x0c, struct.pack(pack_parm, update_address))
        self.write_memory_data(flag_address + 0x10, struct.pack(pack_parm, update_size))
        # set update flag
        self._set_dbg_flag(2)
        # wait text update
        current_update_count = struct.unpack(pack_parm, self.get_mem_dump(flag_address + 0x14, 0x04))[0]
        while current_update_count != original_update_count + 1:
            self.logger.debug("current_update_count: %s , should be: %s" % (hex(current_update_count),
                                                                hex(original_update_count + 1)))
            stack_data = self.get_mem_dump(flag_address, 0x18)
            dbg_status = DebugStack(stack_data)
            self.logger.debug("{:-^{width}}".format("Debug Status", width=80))
            self.logger.debug('##Debuger Status at %s' % hex(flag_address))
            dbg_status.show()

            # set update flag
            self._set_dbg_flag(2)
            current_update_count = struct.unpack(pack_parm, self.get_mem_dump(flag_address + 0x14, 0x04))[0]
            time.sleep(1)
        self.logger.debug('text_update succeed')
        return True

    def init_debugger(self, over_write_address):
        """Initialize Debuger, inject debug shellcode to target memory.

        :param over_write_address: Memory address to store debug shellcode
        :return: True if succeed

        dbg_statck:
            dbg_stack_address + 0xa4 ~ 0x200 = reserve
            dbg_stack_address + 0x20 ~ 0xa0 = regs store address
            dbg_stack_address + 0x18 ~ 0x1C = reserve
            dbg_stack_address + 0x14 = Cache updated count, use to sync update status.
            dbg_stack_address + 0x10 = Cache update size(Default is bp_overwrite_size)
            dbg_stack_address + 0x0c = Address Need Update Cache(Default is Break Point Address)
            dbg_stack_address + 0x08 = Break Point Address + bp_overwrite_size
            dbg_stack_address + 0x04 = Original $RA Value
            dbg_stack_address + 0x00 = Debug Flags(0: Keep loop, 1: Recover, 2: Need update cache)

        """
        self.logger.info("Init debugger asm at address: %s" % hex(over_write_address))
        reg_store_offset = 0x20
        recover_original_ra_asm_code = "lw $ra, 0x04-%s($sp)" % self.dbg_stack_size
        recover_original_ra_asm = self.assemble(recover_original_ra_asm_code, KS_ARCH_MIPS,
                                                KS_MODE_MIPS32,KS_MODE_BIG_ENDIAN if self.endian == 1 else KS_MODE_LITTLE_ENDIAN)[0]

        ##########################
        #     Init DBG Stack     #
        ##########################

        # set flag to zero
        asm_code = "sw $zero, 0x00($sp);"

        # save current return address to stack
        asm_code += "sw $ra, 0x08($sp);"

        # save regs to stack
        stack_offset = reg_store_offset
        for i in range(0x20):
            asm_code += "sw $%s, %s($sp);" % (i, hex(stack_offset))
            stack_offset += 0x04

        # init cache update stack value to default bp address
        asm_code += "addiu $ra, -%s; sw $ra, 0x0c($sp); li $ra, %s; sw $ra, 0x10($sp); sw $zero, 0x14($sp);" % (
            hex(self.bp_overwrite_size),
            hex(self.bp_overwrite_size)
        )

        ##########################
        #        DBG Loop        #
        ##########################

        # call cacheTextUpdate if flag == 0x02
        asm_code += "lw $ra, 0x00($sp); addiu $ra, -0x02; bnez $ra, %s;" % hex(0x08 + 0x0c + 0x10 + 0x04)

        # update cacheTextUpdate execute count
        asm_code += "lw $a0, 0x14($sp); addiu $a0, 0x01; sw $a0, 0x14($sp);"

        j = 'jal' if self.cache_update_address & 0x1 == 0 else 'jalx' #take 16bit into considerate

        # update cache
        asm_code += "lw $a0, 0x0c($sp); lw $a1, 0x10($sp); %s %s;" % (j,hex(self.cache_update_address & 0xffffffe))

        # TODO: recover a0, a1
        # set flag to 0x00
        asm_code += "sw $zero, 0x00($sp);"

        # if flag != 0x01 keep loop
        asm_code += "lw $ra, 0x00($sp); addiu $ra, -0x01; bnez $ra, -%s;" % hex(0x08 + 0x04 + 0x10 + 0x0c + 0x10)


        ##########################
        #         Recover        #
        ##########################

        # update dbg stack cache before recover
        asm_code += "move $a0, $sp; li $a1, %s; %s %s;" % ((hex(self.dbg_stack_size),j,
                                                            hex(self.cache_update_address & 0xffffffe)))
        # recover regs
        stack_offset = reg_store_offset
        for i in range(0x20):
            if i in [29]:
                self.logger.debug("Skip reg: %s" % i)
            else:
                asm_code += "lw $%s, %s($sp);" % (i, hex(stack_offset))
            stack_offset += 0x04

        # return to bp
        asm_code += "lw $ra, 0x08($sp); addiu $ra, -%s; addiu $sp, %s; jr $ra;" % (hex(self.bp_overwrite_size),
                                                                                   hex(self.dbg_stack_size))
        asm_code += "nop;" #Branch delay slot

        self.logger.debug("asm_code: %s" % asm_code)
        asm_list = self.assemble(asm_code, KS_ARCH_MIPS, KS_MODE_MIPS32, KS_MODE_BIG_ENDIAN if self.endian == 1 else KS_MODE_LITTLE_ENDIAN)
        if not asm_list:
            return None
        self.dbg_overwrite_size = len(asm_list * 0x04)
        self.logger.debug("self.dbg_overwrite_size: %s" % hex(self.dbg_overwrite_size))
        # restore $ra by use released sp, hope it's fast enough.
        asm_list[-1] = recover_original_ra_asm
        asm_data = "".join(asm_list).decode("hex")
        self.write_memory_data(over_write_address, asm_data)
        self.debugger_base_address = over_write_address
        return True

    def get_task_regs_from_string(self, raw_data, regs):
        regs_value = {}
        data_list = raw_data.split("\r\n")
        for data in data_list:
            if ("=" in data) and (len(data.split()) == 12):
                reg_data_list = data.split()
                for index in range(0, 12, 3):
                    reg = reg_data_list[index]
                    if reg in regs:
                        try:
                            int(reg_data_list[index + 2], 16)
                            regs_value[reg] = reg_data_list[index + 2]
                        except Exception as err:
                            self.logger.error("ERROR: %s" % err)
                            pass
        return regs_value

    def get_task_stack(self, task):
        """Get task stack with task name

        :param task: Task name
        :return: Task stack data
        """
        cmd = "task -stack %s" % task
        current_task_stack = self.send_and_recvuntil(cmd)
        return current_task_stack

    def get_task_regs(self, task):
        """Get task register value.

        :param task:
        :return:
        """
        current_task_info = self.get_task_info(task, show=False)
        regs = self.get_task_regs_from_string(current_task_info, self.process_regs)
        self.current_task_regs[task] = regs
        return regs

    def task_control(self, task, command):
        """Task control functions

        :param task: task name to control
        :param command: control command['suspend', 'resume', 'stop']
        :return:
        """
        cmd = "task -op %s %s" % (command, task)
        rsp = self.send_and_recvuntil(cmd)
        if "Task %s %s!" % (task, command) in rsp:
            return True
        else:
            self.task_control(task, command)

    def get_tasks_status(self):
        """Get running tasks status

        :return: Current tasks status dict.

        Return Example:
            {
            "inetd": {
                "status": "PEND",
                "pc": 0x80117ad8,
                "sp": 0x8094e8d8
            },
            "tNetTask":{
                "status": "READY",
                "pc": 0x80117ad8,
                "sp": 0x80fe3b90
            }
            }
        """
        current_tasks_status = {}
        cmd = "task -show"
        rsp = self.send_and_recvuntil(cmd)
        if cmd in rsp:
            task_data_list = rsp.split("\r\n")[4:]
            for task_info in task_data_list:
                try:
                    task_info_list = task_info.split()
                    if len(task_info_list) == 9:
                        name, entry, tid, pri, status, pc, sp, errno, delay = task_info_list
                        current_tasks_status[name] = {
                            "status": status,
                            "pc": pc,
                            "sp": sp,
                        }
                except Exception as err:
                    self.logger.error("Some thing error")
                    pass
            return current_tasks_status
        else:
            return None

    def get_netpool_info(self, netpool_address):
        """

        :param netpool_address:
        :return:
        """
        netpool_data = self.get_mem_dump(netpool_address, 100)
        netpool = netPool(netpool_data)
        netpool.show()
        pool_stat_addr = netpool.pPoolStat
        pool_stat = PoolStat(self.get_mem_dump(pool_stat_addr, 0x10))
        pool_stat.show()
        func_tbl_addr = netpool.pFuncTbl
        functbl_data = self.get_mem_dump(func_tbl_addr, 0x28)
        pFuncTbl(functbl_data).show()

    def get_mblk_info(self, mblk_addr):
        print("{:-^{width}}".format("mblk info at %s" % hex(mblk_addr), width=80))
        mblk_data = self.get_mem_dump(mblk_addr, 0x38)  # 0x38 is length
        mblk = mBlk(mblk_data)
        mblk.show()

        print("##clblk at %s" % hex(mblk.pClBlkAddr))
        clblk_hdr_data = self.get_mem_dump(mblk.pClBlkAddr, 0x20)  # 0x38 is length
        clBlk_hdr = clBlk(clblk_hdr_data)
        clBlk_hdr.show()

        mData = self.get_mem_dump(mblk['mBlkHdr'].mData, mblk['mBlkHdr'].mLen)
        print("## mData at: %s with length: %s" % (hex(mblk['mBlkHdr'].mData), hex(mblk['mBlkHdr'].mLen)))
        if mData[:2] == "\x45\x00":
            mPacket = IP(mData)
        elif mData[:2] == "\x41\x41":
            mPacket = Raw(mData)
        else:
            mPacket = Ether(mData)
        mPacket.show()

    def get_task_info(self, task, show=True):
        cmd = "task -desc %s" % task
        current_task_info = self.send_and_recvuntil(cmd)
        if show:
            self.logger.info("current task: %s info is: \r\n %s" % (task, current_task_info))
        return current_task_info

    def show_task_bp_regs(self, task):
        """Display task registers

        :param task: Task name
        :return:
        """
        # TODO: fix regs with debug loop
        regs = self.get_task_regs(task)
        # get original_reg_data from dbg stack
        flag_address = self.current_bp_info["flag_address"]
        original_reg_data = self.get_mem_dump(flag_address + 0x20, 0x80)
        for i in range(0, len(self.process_regs), 0x04):
            print_line = ""
            print_regs = self.process_regs[i:i + 4]
            for print_reg in print_regs:
                if print_reg == "pc":
                    print_line += "{:6}={:>9}\t".format(print_reg, hex(self.current_bp_info["bp_address"])[2:])

                elif print_reg == "ra":
                    # TODO: check value
                    print_line += "{:6}={:>9}\t".format(print_reg, hex(self.current_bp_info["original_ra"])[2:])

                elif print_reg == "sp":
                    print_line += "{:6}={:>9}\t".format(print_reg,
                                                        hex(int(regs[print_reg], 16) + self.dbg_stack_size)[2:])

                elif print_reg in MIPS_REGS_LIST_TO_FIX:
                    reg_offset = MIPS_REGS_LIST_TO_FIX[print_reg]
                    original_reg = struct.unpack("!I", original_reg_data[reg_offset * 0x04: (reg_offset + 1) * 0x04])[0]
                    print_line += "{:6}={:>9}\t".format(print_reg, hex(original_reg)[2:])

                else:
                    print_line += "{:6}={:>9}\t".format(print_reg, regs[print_reg])

            print(print_line)

    def show_task_stack(self, task, lines=10):
        """Display task stack data

        :param task: Task name
        :return:
        """
        print_line = ""
        task_stack = self.get_task_stack(task)
        print_task_stack = task_stack.split("\r\n")[0x03:0x0A]
        # skip debug stack data
        print_task_stack += task_stack.split("\r\n")[0x0c + 0x20:0x0c + 0x20 + lines]
        for line in print_task_stack:
            if '=' in line:
                print_key = line.split()[0]
                print_value = line.split()[2]
                if print_key == 'td_sp':
                    print_value = int(print_value, 16)
                    print_value += self.dbg_stack_size
                    print_value = hex(print_value)[0x2:]
                elif print_key == 'td_stackCurrent':
                    print_value = int(print_value, 16)
                    print_value -= self.dbg_stack_size
                    print_value = hex(print_value)[0x2:]
                print_line += "{:6}={:>9}\t\r\n".format(print_key, print_value)
            else:
                print_line += "{}\r\n".format(line)

        print(print_line)

    def show_task_bp_trace(self, task):
        """Display task breakpoint trace back

        :param task: Task name
        :return:
        """
        trace_data = ""
        trace_data_list = []
        bp_address = self.current_bp_info["bp_address"]
        ra_address = self.current_bp_info["original_ra"]
        bp_asm_data = self.break_points[bp_address]["original_asm"][:4]
        bp_asm = self.disassemble(bp_asm_data, bp_address, CS_ARCH_MIPS, CS_MODE_MIPS32,CS_MODE_BIG_ENDIAN if self.endian == 1 else CS_MODE_LITTLE_ENDIAN)
        trace_data_list.append(bp_asm)
        # get ra asm
        ra_asm_data = None
        for bp_addr in self.break_points:
            if bp_addr <= ra_address <= bp_addr + 0x10:
                offset = ra_address - bp_addr
                ra_asm_data = self.break_points[bp_addr]["original_asm"][offset:offset + 4]
                break
        if not ra_asm_data:
            ra_asm_data = self.get_mem_dump(ra_address, 0x04)
        self.logger.debug("ra_asm_data: %s" % ra_asm_data.encode("hex"))
        ra_asm = self.disassemble(ra_asm_data, ra_address, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN if self.endian == 1 else CS_MODE_LITTLE_ENDIAN)
        self.logger.debug("ra_asm: %s" % ra_asm)
        trace_data_list.append(ra_asm)
        for i in range(len(trace_data_list)):
            self.logger.debug("trace_data_list: %s" % trace_data_list)
            trace_data += "[{}] {}".format(i, trace_data_list[i])
        print(trace_data)

    def get_temp_bp_address(self, bp_address):
        """Calculate temp breakpoint address, this temp breakpoint is used to keep other breakpoints.

        :param bp_address: Breakpoint address
        :return: Temp breakpoint address list.
        """
        try:
            temp_bp_address_list = []
            bp_asm_data = self.break_points[bp_address]["original_asm"]
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | (CS_MODE_BIG_ENDIAN if self.endian == 1 else CS_MODE_LITTLE_ENDIAN))
            md.detail = True
            asm_code_data = {}
            for i in md.disasm(bp_asm_data, bp_address):
                asm_code_data[i.address] = [i.mnemonic, i.op_str]

            for asm in asm_code_data:
                mnemonic = asm_code_data[asm][0]
                op_str = asm_code_data[asm][1]
                # Find Branch asm
                if mnemonic.lower().startswith("b"):
                    self.logger.debug("Found Branch asm at address: %s" % hex(asm))
                    branch_address = int(op_str.split(", ")[1], 16)
                    self.logger.debug("Branch address: %s" % hex(branch_address))
                    if not bp_address - 0x10 <= branch_address <= bp_address + 0x10:
                        temp_bp_address_list.append(branch_address)

                if mnemonic == "jal":
                    self.logger.debug("Found jal at address: %s" % hex(asm))
                    self.logger.debug("Jump to %s" % hex(int(op_str, 16)))
                    # Get jal return address
                    jal_return_address = asm + 0x08
                    # make sure return address less than break point address + 0x10.
                    if not jal_return_address <= bp_address + 0x10:
                        temp_bp_address_list.append(int(op_str, 16))
                        return temp_bp_address_list

                if mnemonic == "jr":
                    self.logger.debug("Found jr at address: %s" % hex(asm))
                    return temp_bp_address_list

            last_asm_addr = max(asm_code_data.keys())
            self.logger.debug("last_asm_addr:%s" % hex(last_asm_addr))
            mnemonic = asm_code_data[last_asm_addr][0]
            if mnemonic.lower().startswith("b"):
                temp_bp_address_list.append(last_asm_addr + 0x08)
            else:
                temp_bp_address_list.append(last_asm_addr + 0x04)

            return temp_bp_address_list

        except Exception as err:
            self.logger.error("ERROR: %s" % err)
            return None

    def create_bp_asm(self, bp_address,is_16bit = 0):
        """Create breakpoint asm code

        :param bp_address: break point address
        :return: Breakpoint shellcode
        """
        # increase stack size
        asm_code = "addiu $sp, -%s;" % hex(self.dbg_stack_size)
        # save original $RA value
        asm_code += "sw $ra, 0x04($sp);"
        if is_16bit == 0:
            # jump to dbg loop
            asm_code += "jal %s;" % (hex(self.debugger_base_address & 0xffffff))
            asm_code += 'nop;' # Branch delay slot
            asm_list = self.assemble(str(asm_code), KS_ARCH_MIPS, KS_MODE_16,KS_MODE_BIG_ENDIAN if self.endian == 1 else KS_MODE_LITTLE_ENDIAN)
            if not asm_list:
                return None
            asm_data = "".join(asm_list).decode("hex")
        else: #16 bit mode
            asm_code += 'nop;nop;nop;' #padding
            # jump to dbg loop
            asm_code += "jalx %s;" % (hex(self.debugger_base_address & 0xffffff))
            asm_code += 'nop;' # Branch delay slot
            asm_data = ASM16(asm_code,self.endian)
        self.logger.debug("asm_code: %s" % asm_code)
        return asm_data
