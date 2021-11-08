# !/usr/bin/env python2
# coding=utf-8
from vx_base_target import VxSerialBaseTarget
from keystone import *
from capstone import *
import struct
import time


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


class VxSerialBaseDebuger(VxSerialBaseTarget):

    def __init__(self, serial=None, serial_until='\r\n#', process_regs=MIPS_REGS, process_type="MIPSBE", endian=1,
                 cache_update_address=0x801011D8, bp_black_list=[], logger=None):
        '''Base VxSerial Debugger

        :param process_regs: Process registers name list, used in capstone (Default: mips registers)
        :param process_type: Process Type String used in asm code label.
        :param endian: 1 = big endian; 2 = little endian.
        :param cache_update_address: VxWorks update cache function(cacheTextUpdate) address.
        :param bp_black_list: Break point address black list dict, avoid add break point to key functions.
        '''
        super(VxSerialBaseDebuger, self).__init__(serial=serial, serial_until=serial_until, logger=logger)
        self.debugger_base_address = None
        self.break_points = {}
        self.break_points_need_add = []
        self.current_task_regs = {}     # Current task regs dict
        self.current_bp_info = {
            "bp_address": 0,            # Breakpoint address
            "bp_type": 0,               # Breakpoint type
            "condition": None,          # Condition function object
            "flag_address": 0,          # Debug flag address
            "original_ra": 0,           # Original ra register value
        }
        self.cache_update_address = cache_update_address
        self.dbg_stack_size = 0x200
        self.bp_overwrite_size = 0x10       # Breakpoint overwrite size
        self.dbg_overwrite_size = 0x1
        self.process_regs = process_regs
        self.process_type = process_type
        self.endian = endian
        self.bp_black_list = bp_black_list

    def text_update(self, update_address, update_size):
        """Update Process cache

        :param update_address: Memory address to update.
        :param update_size: Cache update size
        :return: True if update succeed
        """
        self.not_implemented('text_update')

    def init_debugger(self, over_write_address):
        """Initialize Debuger, inject debug shellcode to target memory.

        :param over_write_address: Memory address to store debug shellcode
        :return: True if succeed

        """
        self.not_implemented('init_debugger')

    def restone_bp_asm(self, bp_address):
        '''Restone breakpoint asm code.

        :param bp_address: Breakpoint Address
        :return:
        '''
        original_asm = self.break_points[bp_address]["original_asm"]
        self.write_memory_data(bp_address, original_asm)
        # update chache
        self.text_update(bp_address, self.bp_overwrite_size)

    def get_task_stack(self, task):
        """Get task stack with task name

        :param task: Task name
        :return: Task stack data
        """
        self.not_implemented('get_task_stack')

    def get_task_regs(self, task):
        """Get task register value.

        :param task:
        :return:
        """
        self.not_implemented('get_task_regs')

    def task_control(self, task, command):
        """Task control functions

        :param task: task name to control
        :param command: control command['suspend', 'resume', 'stop']
        :return:
        """
        self.not_implemented("task_control")

    def suspend_task(self, task):
        """Suspend a task.

        :param task: Task name
        :return: True if task is suspended
        """
        if self.task_control(task, 'suspend'):
            return True
        else:
            self.suspend_task(task)

    def resume_task(self, task):
        """Resume a task.

        :param task: Task name
        :return: True if task is resume
        """
        if self.task_control(task, 'resume'):
            return True
        else:
            self.suspend_task(task)

    def suspend_other_task(self, task, white_list=["tCmdTask", "tNetTask"]):
        """Suspend other task

        :param task: task name to keep
        :param white_list: task name in white list will not be suspended.
        :return:
        """
        white_list.append(task)
        current_tasks_status = self.get_tasks_status()
        for task_need_suspend in current_tasks_status:
            if task_need_suspend not in white_list:
                self.suspend_task(task_need_suspend)

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
        self.not_implemented("get_tasks_status")

    def _is_address_in_debug_loop(self, address):
        if self.debugger_base_address <= address <= self.debugger_base_address + self.dbg_overwrite_size:
            return True
        else:
            return False

    def _is_task_in_debug_loop(self, task):
        task_regs = self.get_task_regs(task)
        # TODO: Need handle Text Update loop in
        if "pc" in task_regs:
            task_pc = int(task_regs["pc"], 16)
            return self._is_address_in_debug_loop(task_pc)
        else:
            # keep read until get pc reg.
            return self._is_task_in_debug_loop(task)

    def is_bp_in_black_list(self, bp_address):
        """Check is breakpoint address in blacklist

        :param bp_address: Breakpoint address.
        :return: True if address in blacklist, False other wise.
        """
        in_black_list = False
        for black_list in self.bp_black_list:
            start_address, end_address = self.bp_black_list[black_list]
            if start_address <= bp_address <= end_address:
                self.logger.warn("break address at %s is in black list" % hex(bp_address))
                in_black_list = True
        #
        for breakpoint in self.break_points:
            if breakpoint - self.bp_overwrite_size < bp_address < breakpoint + self.bp_overwrite_size:
                self.logger.warn("Already have breakpoint at address %s" % hex(bp_address))
                in_black_list = True
        return in_black_list

    def is_task_on_break_point(self, task):
        """ Check is task on break point, if task hit break point update current breakpoint status.

        :param task: Task name.
        :return: If on break point,return break point address, False other wise.
        """
        if self._is_task_in_debug_loop(task):
            if task not in self.current_task_regs:
                self.get_task_regs(task)
            pack_parm = ">I"
            if self.endian == 2:
                pack_parm = "<I"
            sp = int(self.current_task_regs[task]["sp"], 16)
            break_point = (struct.unpack(pack_parm, self.get_mem_dump(sp + 0x08, 0x04))[0] - self.bp_overwrite_size) & 0xfffffffe # take 16bit in considerate
            original_ra = struct.unpack(pack_parm, self.get_mem_dump(sp + 0x04, 0x04))[0]
            self.current_bp_info["bp_address"] = break_point  # break point address = $ra - 0x08
            self.current_bp_info["flag_address"] = sp
            self.current_bp_info["original_ra"] = original_ra
            # get break point info.
            try:
                self.current_bp_info["bp_type"] = self.break_points[break_point]["bp_type"]
                self.current_bp_info["condition"] = self.break_points[break_point]["condition"]

            except Exception as err:
                self.logger.error("ERROR: %s" % err)

            self.logger.debug("task hit break_point: %s" % hex(break_point))
            return break_point
        return False

    def keep_break_point(self):
        for bp_address in self.break_points_need_add:
            asm_data = self.create_bp_asm(bp_address)
            if not asm_data:
                self.logger.error("Can't create break point asm")
                return False
            self.write_memory_data(bp_address, asm_data)
            # cleanup list after break point added
            del self.break_points_need_add[self.break_points_need_add.index(bp_address)]
            # update cache
            self.text_update(bp_address, self.bp_overwrite_size)

    def remove_all_temp_bp(self):
        for bp_addr in self.break_points.keys():  # use keys() to avoid "dictionary changed size during iteration"
            bp_type = self.break_points[bp_addr]["bp_type"]
            if bp_type == 1:
                self.restone_bp_asm(bp_addr)
                # cleanup list after temp break point restore
                del self.break_points[bp_addr]

    def remove_break_point(self,bp_addr):
        self.restone_bp_asm(bp_addr)
        # cleanup list after temp break point restore
        del self.break_points[bp_addr]


    def _is_on_break_point(self):
        """Check did any task hit break point.

        :return: task name which hit break point
        """
        current_tasks_status = self.get_tasks_status()
        if not current_tasks_status:
            return None
        # TODO: need handle multi task hit breakpoint.
        for task in current_tasks_status:
            self.logger.debug(current_tasks_status[task])
            try:
                if self._is_address_in_debug_loop(int(current_tasks_status[task]['pc'], 16)):
                    return task
            except:
                return None
        return None

    def wait_break(self):
        """Wait until some task hit the breakpoint

        :return: Task name
        """
        self.logger.info("Wait. use ctrl+c to stop.")
        try:
            # Wait for any task hit break point.
            task = self._is_on_break_point()
            while task is None:
                task = self._is_on_break_point()
                time.sleep(0.2)
            # Get break point by task
            current_breakpoint = self.is_task_on_break_point(task)
            while not current_breakpoint:
                current_breakpoint = self.is_task_on_break_point(task)
                time.sleep(0.2)

            # keep break point in break_points_need_add.
            self.keep_break_point()

            # get break point type
            current_bp_type = self.break_points[current_breakpoint]["bp_type"]
            current_bp_condition = self.break_points[current_breakpoint]["condition"]
            if current_bp_type == 0:
                self.logger.info("Task: %s hit break point %s" % (task, hex(self.current_bp_info["bp_address"])))
                if callable(current_bp_condition):
                    try:
                        self.logger.info("current_bp_condition!")
                        if current_bp_condition(self, task, current_breakpoint):
                            self.show_task_bp_context(task)
                            return task
                        else:
                            self.task_resume(task)
                    except Exception as err:
                        self.logger.error("condition exec error.")
                        self.logger.error("ERROR: %s" % err)

                self.show_task_bp_context(task)
                return task

            elif current_bp_type == 1:
                # self.show_task_bp_context(task)
                self.task_resume(task)
                return

            elif current_bp_type == 2:
                # TODO: implement later.
                self.task_resume(task)

        except KeyboardInterrupt:
            return
        except Exception as err:
            self.logger.error("ERROR: %s" % err)
            return

    def wait_task_break(self, task):
        """Wait until task hit the breakpoint

        :param task: Task name
        :return:
        """
        self.logger.info("Wait task break. use ctrl+c to stop.")
        try:
            current_breakpoint = self.is_task_on_break_point(task)
            while not current_breakpoint:
                current_breakpoint = self.is_task_on_break_point(task)
                time.sleep(0.2)

            # keep break point in break_points_need_add.
            self.keep_break_point()

            # get break point type
            current_bp_type = self.break_points[current_breakpoint]["bp_type"]
            current_bp_condition = self.break_points[current_breakpoint]["condition"]
            if current_bp_type == 0:
                self.logger.info("Task: %s hit break point %s" % (task, hex(self.current_bp_info["bp_address"])))
                if callable(current_bp_condition):
                    try:
                        if current_bp_condition(self, task, current_breakpoint):
                            self.show_task_bp_context(task)
                            return
                        else:
                            self.task_resume(task)
                    except Exception as err:
                        self.logger.error("condition exec error.")
                        self.logger.error("ERROR: %s" % err)

                self.show_task_bp_context(task)
                return

            elif current_bp_type == 1:
                self.logger.debug("Hit temp break point.")
                self.task_resume(task)

        except KeyboardInterrupt:
            return
        except Exception as err:
            self.logger.error("ERROR: %s" % err)
            return

    def show_task_bp_regs(self, task):
        """Display task registers

        :param task: Task name
        :return:
        """
        self.not_implemented("show_task_bp_regs")

    def show_task_stack(self, task):
        """Display task stack data

        :param task: Task name
        :return:
        """
        self.not_implemented("show_task_stack")

    def show_task_bp_asm(self, task):
        """Display task breakpoint asm code

        :param task: Task name
        :return:
        """
        bp_address = self.current_bp_info["bp_address"]
        bp_asm_data = self.break_points[bp_address]["original_asm"]
        bp_asm_code = self.disassemble(bp_asm_data, bp_address, CS_ARCH_MIPS, CS_MODE_MIPS32,CS_MODE_BIG_ENDIAN if self.endian == 1 else  CS_MODE_LITTLE_ENDIAN)
        print(bp_asm_code)

    def show_task_bp_trace(self, task):
        """Display task breakpoint trace back

        :param task: Task name
        :return:
        """
        self.not_implemented('show_task_bp_trace')

    def show_task_bp_context(self, task):
        """Display task breakpoint context

        :param task: Task name
        :return:
        """
        # registers
        print("{:-^{width}}".format("registers", width=80))
        self.show_task_bp_regs(task)
        # stack
        print("{:-^{width}}".format("stack", width=80))
        self.show_task_stack(task)
        # asm
        asm_head = "asm:{}".format(self.process_type)
        print("{:-^{width}}".format(asm_head, width=80))
        self.show_task_bp_asm(task)
        # trace
        print("{:-^{width}}".format("trace", width=80))
        self.show_task_bp_trace(task)

    def interactive(self):
        self.serial.interactive()

    def get_temp_bp_address(self, bp_address):
        """Calculate temp breakpoint address, this temp breakpoint is used to keep other breakpoints.

        :param bp_address: Breakpoint address
        :return: Temp breakpoint address list.
        """
        self.not_implemented('get_temp_bp_address')

    def add_temp_bp(self, bp_addr):
        temp_bp_list = self.get_temp_bp_address(bp_addr)
        if temp_bp_list:
            for bp_addr in temp_bp_list:
                self.add_break_point(bp_addr, bp_type=1)

    def _set_dbg_flag(self, flag):
        '''Update debug flag.

        :param flag: Debug flag, 1=resume, 2=update cache.
        :return:
        '''
        flag_address = self.current_bp_info["flag_address"]
        pack_parm = ">I"
        if self.endian == 2:
            pack_parm = "<I"
        flag_value = struct.pack(pack_parm, flag)
        self.write_memory_data(flag_address, flag_value, check=False)

    def task_resume(self, task, wait=True):
        # check task status
        if not self.is_task_on_break_point(task):
            self.logger.warn("task %s, is not on break point." % task)
            return None

        bp_addr = self.current_bp_info["bp_address"]
        flag_address = self.current_bp_info["flag_address"]
        # get break point type
        current_bp_type = self.break_points[bp_addr]["bp_type"]
        if current_bp_type == 0:
            # Add break_points to keep list
            self.break_points_need_add.append(bp_addr)
            self.add_temp_bp(bp_addr)
            # recover break point asm
            self.logger.debug("Recover break point asm of address: %s" % bp_addr)
            self.restone_bp_asm(bp_addr)

        elif current_bp_type == 1:
            # after break point keep remove all temp bp.
            self.remove_all_temp_bp()

        # set dbg_flag to 1
        self.logger.debug("Set dbg_flag to 1, flag_address: %s" % hex(flag_address))
        self._set_dbg_flag(1)
        self.logger.debug("Check task in resume.")

        while self.is_task_on_break_point(task) == bp_addr:
            # TODO: Need find a method to avoid skipping next breakpoint.
            self.logger.debug("Target not resume, try again.")
            self._set_dbg_flag(1)

        self.logger.info("task is resume.")
        # clean up dbg status
        self.logger.debug("cleanup dbg status.")
        self.current_bp_info = {"bp_address": 0, "flag_address": 0}
        if wait:
            self.wait_task_break(task)

    def create_bp_asm(self, bp_address,is_16bit):
        """Create breakpoint asm code

        :param bp_address: break point address
        :return: Breakpoint shellcode
        """
        self.not_implemented("create_bp_asm")

    def add_break_point(self, bp_address, is_16bit = 0,bp_type=0, condition=None):
        """Add break point

        :param bp_address: Break point address you want to Add.
        :param is_16bit 0 = 32 bit MIPS
                        1 = 16 bit MIPS
        :param bp_type: 0 = normal break point should will keep
                        1 = temp break point, used to keep normal break point add automatically.
                            will be removed after hit normal break point.
        :param condition: condition function, function return True to break, False to continue.
        :return: True if break point added, False otherwise.
        """
        if self.is_bp_in_black_list(bp_address):
            return False

        if bp_type == 0:
            self.logger.info("Add breakpoint at %s" % hex(bp_address))
        # create break point asm
        asm_data = self.create_bp_asm(bp_address,is_16bit)
        if not asm_data:
            self.logger.error("Can't create break point asm")
            return False
        asm_length = len(asm_data)
        # get original_asm
        original_asm = self.get_mem_dump(bp_address, asm_length)
        bp_asm_code = self.disassemble(original_asm, bp_address, CS_ARCH_MIPS, CS_MODE_MIPS32,CS_MODE_BIG_ENDIAN if self.endian == 1 else CS_MODE_LITTLE_ENDIAN)
        self.logger.debug("original_asm: %s" % original_asm)
        self.bp_overwrite_size = asm_length
        self.write_memory_data(bp_address, asm_data)
        # call text_update
        self.text_update(bp_address, self.bp_overwrite_size)
        self.break_points[bp_address] = {
            "bp_type": bp_type,
            "original_asm": original_asm,
            "asm_code": bp_asm_code,
            "condition": condition,
        }
        return True

    def assemble(self, asm_code, asm_arch, asm_mode, asm_endian):
        """

        :param asm_code:
        :param asm_arch:
        :param asm_mode:
        :param asm_endian:
        :return:
        """
        asm = []
        self.logger.debug("asm_code: %s" % asm_code)
        try:
            ks = Ks(asm_arch, asm_mode | asm_endian)
            encoding, count = ks.asm(asm_code)
            asm_data = "".join(map(chr, encoding))
            self.logger.debug("asm_data:%s" % asm_data.encode("hex"))
            self.logger.debug("len(asm_data): %s" % len(asm_data))
            for i in range(0, len(asm_data), 4):
                self.logger.debug("asm_data[i:i + 4]: %s" % asm_data[i:i + 4].encode("hex"))
                asm.append(asm_data[i:i + 4].encode("hex"))
            return asm
        except KsError as err:
            self.logger.error("ERROR: %s" % err)
            return None

    def disassemble(self, binary, base_address, asm_arch, asm_mode, asm_endian):
        """

        :param binary:
        :param base_address:
        :param asm_arch:
        :param asm_mode:
        :param asm_endian:
        :return:
        """
        self.logger.debug("binary: %s" % binary.encode("hex"))
        try:
            self.logger.debug("IN!!!")
            md = Cs(asm_arch, asm_mode | asm_endian)
            asm_code = ""
            for i in md.disasm(binary, base_address):
                self.logger.debug("asm_code: %s" % asm_code)
                asm_code += "{}:\t{}\t{}\r\n".format(hex(i.address), i.mnemonic, i.op_str)
            self.logger.debug("asm_code: %s" % asm_code)
            return asm_code

        except Exception as err:
            self.logger.error("ERROR: %s" % err)
            return None
