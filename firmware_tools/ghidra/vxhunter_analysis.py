import json
from ghidra.program.model.symbol import RefType, SourceType
from vxhunter_core import *
from vxhunter_utility.common import create_initialized_block, get_logger
from vxhunter_utility.function_analyzer import *
from vxhunter_utility.symbol import *


class VxAnalyzer(object):
    def __init__(self, logger=None):
        self._vx_version = None
        self.report = []
        self.timer_log = []
        self.timer = Timer()

        if logger is None:
            self.logger = get_logger(self.__class__.__name__)
        else:
            self.logger = logger

        # self.logger.setLevel(10)

    def analyze_bss(self):
        self.report.append('{:-^60}'.format('analyze bss info'))
        self.logger.info("Start analyze bss info")
        target_function = get_function("bzero")
        if target_function:
            parms_data = dump_call_parm_value(call_address=target_function.getEntryPoint(), search_functions=['sysStart',
                                                                                                              'usrInit',
                                                                                                              '_sysStart',
                                                                                                              '_usrInit',
                                                                                                              ])
            for call_addr in parms_data:
                call_parms = parms_data[call_addr]
                bss_start_address = call_parms['parms']['parm_1']['parm_value']
                self.logger.debug("bss_start_address: {}".format(bss_start_address))
                try:
                    if getDataAt(toAddr(bss_start_address)).isPointer():
                        self.logger.debug("bzero parm_1 is pointer")
                        bss_start_address = getDataAt(toAddr(bss_start_address)).getValue().offset
                        self.logger.debug("Real bss_start_address: {}".format(bss_start_address))

                except BaseException as err:
                    self.logger.error(err)

                self.logger.info("call_parms: {}".format(call_parms))
                self.report.append("bss_start_address: {:#010x}".format(bss_start_address))
                bss_length = call_parms['parms']['parm_2']['parm_value']
                if not bss_length:
                    self.logger.error("Can't calculate bss length.")
                    self.report.append("Can't calculate bss length.")
                    break
                self.report.append("bss_end_address: {}".format(hex(bss_start_address + bss_length - 1)))
                self.report.append("bss_length: {}".format(hex(bss_length)))
                self.logger.info("bss_end_address: {}".format(hex(bss_start_address + bss_length - 1)))
                self.logger.info("bss_length: {}".format(hex(bss_length)))
                if not is_address_in_current_program(toAddr(bss_start_address)):
                    self.report.append("bss block not in current program, adding...")
                    if create_initialized_block(block_name=".bss", start_address=toAddr(bss_start_address),
                                                length=bss_length):
                        self.logger.info("bss block created")
                    else:
                        self.logger.info("Can't create bss block, you can create it manually")

        else:
            self.logger.error("Can't find bzero function in firmware")
        self.report.append('{}\r\n'.format("-" * 60))

    def analyze_login_accouts(self):
        hard_coded_accounts = {}
        self.logger.info("analyze loginUserAdd function")
        self.report.append("{:-^60}".format("analyze loginUserAdd function"))
        target_function = get_function("loginUserAdd")
        if target_function:
            parms_data = dump_call_parm_value(target_function.getEntryPoint())
            for call_addr in parms_data:
                call_parms = parms_data[call_addr]
                parm_data_string = ""
                user_name = call_parms["parms"]["parm_1"]["parm_data"]
                if isinstance(user_name, DataDB):
                    user_name = user_name.value
                pass_hash = call_parms["parms"]["parm_2"]["parm_data"]
                if isinstance(pass_hash, DataDB):
                    pass_hash = pass_hash.value
                if user_name or pass_hash:
                    hard_coded_accounts[call_parms["call_addr"]] = {
                        "user_name": user_name,
                        "pass_hash": pass_hash
                    }

                for parm in sorted(call_parms['parms'].keys()):
                    parm_value = call_parms['parms'][parm]['parm_value']
                    parm_data = call_parms['parms'][parm]['parm_data']
                    if parm_value:
                        parm_data_string += "{}({:#010x}), ".format(parm_data, parm_value)
                    else:
                        # Handle None type
                        parm_data_string += "{}({}), ".format(parm_data, parm_value)
                # remove end ', '
                parm_data_string = parm_data_string.strip(', ')
                logger.debug("{}({}) at {:#010x} in {}({:#010x})".format(target_function.name, parm_data_string,
                                                                         call_parms['call_addr'].offset,
                                                                         call_parms['refrence_function_name'],
                                                                         call_parms['refrence_function_addr'].offset
                                                                         ))
        else:
            self.report.append("Can't find loginUserAdd function in firmware")

        self.logger.info("Found {} hard coded accounts".format(len(hard_coded_accounts)))
        self.report.append("Found {} hard coded accounts".format(len(hard_coded_accounts)))
        for account in hard_coded_accounts:
            self.logger.info("user_name: {}, pass_hash: {}, added at address: {}".format(
                hard_coded_accounts[account]['user_name'],
                hard_coded_accounts[account]['pass_hash'],
                hex(account.offset)
            ))
            self.report.append("user_name: {}, pass_hash: {}, added at address: {}".format(
                hard_coded_accounts[account]['user_name'],
                hard_coded_accounts[account]['pass_hash'],
                hex(account.offset)
            ))

        self.report.append('{}\r\n'.format("-" * 60))

    def analyze_service(self):
        service_status = {}
        self.logger.info('analyze services')
        self.report.append('{:-^60}'.format('analyze services'))

        for service in sorted(vxworks_service_keyword.keys()):
            service_status[service] = "Not available"
            for service_function in vxworks_service_keyword[service]:
                target_function = get_function(service_function)
                if target_function:
                    # print("Found {} in firmware, service {} might available".format(service_function, service))
                    service_status[service] = "available"

        for service in sorted(service_status.items(), key=lambda x: x[1], reverse=True):
            self.logger.info('{}: {}'.format(service[0], service[1]))
            self.report.append('{}: {}'.format(service[0], service[1]))
        self.report.append('{}\r\n'.format("-" * 60))

    def analyze_symbols(self):
        self.logger.info('analyze symbols using sysSymTbl')
        self.report.append('{:-^60}'.format('analyze symbols using sysSymTbl'))
        function_manager = currentProgram.getFunctionManager()
        functions_count_before = function_manager.getFunctionCount()
        sys_sym_tbl = get_symbol('sysSymTbl')

        if not sys_sym_tbl:
            self.report.append('{}\r\n'.format("-" * 60))
            return

        if not is_address_in_current_program(sys_sym_tbl.getAddress()):
            self.report.append('{}\r\n'.format("-" * 60))
            return

        sys_sym_addr = toAddr(getInt(sys_sym_tbl.getAddress()))

        if not is_address_in_current_program(sys_sym_addr):
            self.logger.info("sys_sym_addr({:#010x}) is not in current_program".format(sys_sym_addr.getOffset()))
            self.report.append("sys_sym_addr({:#010x}) is not in current_program".format(sys_sym_addr.getOffset()))
            self.report.append('{}\r\n'.format("-" * 60))
            return

        if sys_sym_addr.getOffset() == 0:
            self.report.append('{}\r\n'.format("-" * 60))
            return

        else:
            try:
                if not self._vx_version:
                    vx_version = askChoice("Choice", "Please choose VxWorks main Version ", ["5.x", "6.x"], "5.x")
                    if vx_version == u"5.x":
                        self._vx_version = 5

                    elif vx_version == u"6.x":
                        self._vx_version = 6
                        self.logger.info(("VxHunter didn't support symbols analyze for VxWorks version 6.x"))

                if self._vx_version == 5:
                    self.logger.info(("Functions count: {}(Before analyze) ".format(functions_count_before)))
                    self.report.append("Functions count: {}(Before analyze) ".format(functions_count_before))
                    create_struct(sys_sym_addr, vx_5_sys_symtab)
                    hash_tbl_addr = toAddr(getInt(sys_sym_addr.add(0x04)))
                    create_struct(hash_tbl_addr, vx_5_hash_tbl)
                    hash_tbl_length = getInt(hash_tbl_addr.add(0x04))
                    hash_tbl_array_addr = toAddr(getInt(hash_tbl_addr.add(0x14)))
                    hash_tbl_array_data_type = ArrayDataType(vx_5_sl_list, hash_tbl_length, vx_5_sl_list.getLength())
                    create_struct(hash_tbl_array_addr, hash_tbl_array_data_type)
                    self.logger.info("Start fix functions")
                    for i in range(0, hash_tbl_length):
                        list_head = toAddr(getInt(hash_tbl_array_addr.add(i * 8)))
                        list_tail = toAddr(getInt(hash_tbl_array_addr.add((i * 8) + 0x04)))
                        if is_address_in_current_program(list_head) and is_address_in_current_program(list_tail):
                            fix_symbol_by_chains(list_head, list_tail, vx_version)
            except Exception as err:
                self.logger.error(err)

            finally:
                # Wait analyze finish.
                self.logger.info("Waiting for pending analysis to complete...")
                analyzeChanges(currentProgram)
                functions_count_after = function_manager.getFunctionCount()
                self.logger.info("Functions count: {}(After analyze) ".format(functions_count_after))
                self.logger.info("VxHunter found {} new functions".format(
                    functions_count_after - functions_count_before))
                self.report.append("Functions count: {}(After analyze) ".format(functions_count_after))
                self.report.append("VxHunter found {} new functions".format(
                    functions_count_after - functions_count_before))
                self.report.append('{}\r\n'.format("-" * 60))

    def analyze_function_xref_by_symbol_get(self):
        self.logger.info('{:-^60}'.format('analyze symFindByName function call'))
        self.report.append('{:-^60}'.format('analyze symFindByName function call'))

        # symFindByName analyze
        target_function = get_function("symFindByName")

        if target_function:
            parms_data = dump_call_parm_value(call_address=target_function.getEntryPoint())
            logger.debug("Found {} symFindByName call".format(len(parms_data)))
            logger.debug("parms_data.keys(): {}".format(parms_data.keys()))
            currentReferenceManager = currentProgram.getReferenceManager()
            for call_addr in parms_data:
                try:
                    call_parms = parms_data[call_addr]
                    logger.debug("call_parms: {}".format(call_parms))
                    if 'parm_2' not in call_parms['parms'].keys():
                        continue

                    searched_symbol_name_ptr = call_parms['parms']['parm_2']['parm_data']
                    if isinstance(searched_symbol_name_ptr, DataDB):
                        searched_symbol_name = searched_symbol_name_ptr.value
                        if isinstance(searched_symbol_name, GenericAddress):
                            if is_address_in_current_program(searched_symbol_name):
                                searched_symbol_name = getDataAt(searched_symbol_name)
                        logger.debug("type(searched_symbol_name): {}".format(type(searched_symbol_name)))
                        logger.debug("searched_symbol_name: {}".format(searched_symbol_name))
                        if isinstance(searched_symbol_name, unicode) is False:
                            searched_symbol_name = searched_symbol_name.value
                        self.logger.info("Found symFindByName({}) call at {:#010x}".format(
                            searched_symbol_name, call_parms['call_addr'].offset))
                        self.report.append("Found symFindByName({}) call at {:#010x}".format(
                            searched_symbol_name, call_parms['call_addr'].offset))

                        to_function = get_function(searched_symbol_name, None)

                        if to_function:
                            ref_to = to_function.getEntryPoint()
                            ref_from = call_parms['call_addr']
                            currentReferenceManager.addMemoryReference(ref_from, ref_to, RefType.READ,
                                                                       SourceType.USER_DEFINED, 0)
                            self.logger.info("Add Reference for {}( {:#010x} ) function call at {:#010x} in {}( {:#010x} )".format(
                                to_function,
                                ref_to.offset,
                                call_parms['call_addr'].offset,
                                call_parms['refrence_function_name'],
                                call_parms['refrence_function_addr'].offset
                            )
                            )
                            self.report.append("Add Reference for {}( {:#010x} ) function call at {:#010x} in {}( {:#010x} )".format(
                                to_function,
                                ref_to.offset,
                                call_parms['call_addr'].offset,
                                call_parms['refrence_function_name'],
                                call_parms['refrence_function_addr'].offset
                            ))

                        else:
                            self.logger.error("Can't find {} symbol in firmware".format(searched_symbol_name))

                        logger.debug("{}({}) at {:#010x} in {}({:#010x})".format(target_function.name, searched_symbol_name,
                                                                                 call_parms['call_addr'].offset,
                                                                                 call_parms['refrence_function_name'],
                                                                                 call_parms['refrence_function_addr'].offset
                                                                                 ))
                except Exception as err:
                    self.logger.error(err)

        else:
            self.logger.error("Can't find {} function in firmware".format(target_function))

        self.report.append('{}\r\n'.format("-" * 60))

    def analyze_netpool(self):
        if not self._vx_version:
            vx_version = askChoice("Choice", "Please choose VxWorks main Version ", ["5.x", "6.x"], "5.x")

            if vx_version == u"5.x":
                self._vx_version = 5

            elif vx_version == u"6.x":
                self._vx_version = 6
                self.logger.error("VxHunter didn't support netpool analyze for VxWorks version 6.x")
                self.report.append("VxHunter didn't support netpool analyze for VxWorks version 6.x")
                return

        self.logger.info('analyze netpool')
        self.report.append('{:-^60}'.format('analyze netpool'))
        pools = ["_pNetDpool", "_pNetSysPool"]
        for pool in pools:
            self.report.append(('{:-^20}'.format(pool)))
            net_dpool = get_symbol(pool)
            net_dpool_addr = toAddr(getInt(net_dpool.getAddress()))

            if not is_address_in_current_program(net_dpool_addr):
                self.logger.error("{}({:#010x}) is not in current_program".format(pool, net_dpool_addr.getOffset()))
                self.report.append("{}({:#010x}) is not in current_program".format(pool, net_dpool_addr.getOffset()))

            elif net_dpool_addr.getOffset() == 0:
                pass

            self.logger.info("Found {} at {:#010x}".format(pool, net_dpool_addr.getOffset()))
            self.report.append("Found {} at {:#010x}".format(pool, net_dpool_addr.getOffset()))

            try:
                if self._vx_version == 5:
                    net_pool_info = fix_netpool(net_dpool_addr, self._vx_version)
                    pool_addr = net_pool_info["pool_addr"]
                    pool_func_tbl_addr = net_pool_info["pool_func_tbl_addr"]
                    pool_status_addr = net_pool_info["pool_status_addr"]
                    pool_table_addr = net_pool_info["pool_table_addr"]
                    self.report.append("Pool address: {:#010x}".format(pool_addr))
                    self.report.append("Pool function table address: {:#010x}".format(pool_func_tbl_addr))
                    self.report.append("Pool status address: {:#010x}".format(pool_status_addr))
                    self.report.append("Pool table address: {:#010x}".format(pool_table_addr))
                    cl_pool_count = 0
                    for cl_pool_info in net_pool_info["cl_pool_info"]:
                        cl_pool_addr = cl_pool_info["cl_pool_addr"]
                        cl_pool_num = cl_pool_info["cl_pool_num"]
                        cl_pool_num_free = cl_pool_info["cl_pool_num_free"]
                        cl_pool_size = cl_pool_info["cl_pool_size"]
                        cl_pool_usage = cl_pool_info["cl_pool_usage"]
                        cl_head_addr = cl_pool_info["cl_head_addr"]
                        cl_pool_name = "Clpool {}".format(cl_pool_count)
                        self.report.append(('  {:-^20}'.format(cl_pool_name)))
                        cl_pool_data = "  address: {:#010x} block head Address: {:#010x} "\
                                       "buff size: {} numbers: {} free numbers: {} usage: {} ".format(
                            cl_pool_addr, cl_head_addr, cl_pool_size, cl_pool_num, cl_pool_num_free, cl_pool_usage)
                        self.report.append(cl_pool_data)
                        cl_pool_count += 1

            except Exception as err:
                self.logger.error(err)

        self.report.append('{}\r\n'.format("-" * 60))

    def analyze_active_task(self):
        self.logger.info('analyze active task')
        self.report.append('{:-^60}'.format('analyze task'))
        active_qhead = get_symbol("activeQHead")
        if active_qhead:
            active_qhead_addr = active_qhead.getAddress()
            create_struct(active_qhead_addr, vx_5_q_head)
            active_task_head_ptr = active_qhead_addr.add(0x04)
            active_task_head = toAddr(getInt(active_task_head_ptr))
            if not is_address_in_current_program(active_task_head):
                self.report.append('{}\r\n'.format("-" * 60))
                return

            tcb_addr = active_task_head.add(-0x20)
            first_tcb_addr = tcb_addr

            while True:
                # TODO: Print task info pretty
                tcb_info = fix_tcb(tcb_addr, self._vx_version)
                task_name = tcb_info["task_name"]
                task_entry_addr = tcb_info["task_entry_addr"]
                task_entry_name = tcb_info["task_entry_name"]
                task_stack_base = tcb_info["task_stack_base"]
                task_stack_limit = tcb_info["task_stack_limit"]
                task_stack_limit_end = tcb_info["task_stack_limit_end"]
                task_info_data = "  Task name: {}  Entry: {}({:#010x})  tid: {:#010x}  " \
                                "stack base: {:#010x}   stack limit {:#010x}   stack end {:#010x}".format(
                    task_name, task_entry_name, task_entry_addr, tcb_addr.getOffset(), task_stack_base,
                    task_stack_limit, task_stack_limit_end
                )
                self.report.append(task_info_data)
                next_active_task_ptr = tcb_addr.add(0x24)
                next_active_task = toAddr(getInt(next_active_task_ptr))
                if next_active_task.getOffset() == 0:
                    break
                tcb_addr = next_active_task.add(-0x20)
                if tcb_addr == first_tcb_addr or is_address_in_current_program(tcb_addr) is False:
                    break

        self.report.append('{}\r\n'.format("-" * 60))

    def print_report(self):
        for line in self.report:
            print(line)

        # Print timer
        print('{:-^60}'.format(self.__class__.__name__ + " timer"))
        for line in self.timer_log:
            print(line)
        print('{}\r\n'.format("-" * 60))

    def start_analyzer(self):
        self.timer.reset()
        self.analyze_bss()
        timer_log = "analyze bss takes {:.3f} seconds".format(self.timer.get_timer())
        self.logger.info(timer_log)
        self.timer_log.append(timer_log)

        self.timer.reset()
        self.analyze_login_accouts()
        timer_log = "analyze loginUserAdd function takes {:.3f} seconds".format(self.timer.get_timer())
        self.logger.info(timer_log)
        self.timer_log.append(timer_log)

        self.timer.reset()
        self.analyze_service()
        timer_log = "analyze services takes {:.3f} seconds".format(self.timer.get_timer())
        self.logger.info(timer_log)
        self.timer_log.append(timer_log)

        self.timer.reset()
        self.analyze_symbols()
        timer_log = "analyze symbols takes {:.3f} seconds".format(self.timer.get_timer())
        self.logger.info(timer_log)
        self.timer_log.append(timer_log)

        self.timer.reset()
        self.analyze_netpool()
        timer_log = "analyze netpool takes {:.3f} seconds".format(self.timer.get_timer())
        self.logger.info(timer_log)
        self.timer_log.append(timer_log)

        self.timer.reset()
        self.analyze_function_xref_by_symbol_get()
        timer_log = "analyze symFindByName function call takes {:.3f} seconds".format(self.timer.get_timer())
        self.logger.info(timer_log)
        self.timer_log.append(timer_log)

        self.timer.reset()
        self.analyze_active_task()
        timer_log = "analyze active task takes {:.3f} seconds".format(self.timer.get_timer())
        self.logger.info(timer_log)
        self.timer_log.append(timer_log)


if __name__ == '__main__':
    analyzer = VxAnalyzer()
    analyzer.start_analyzer()
    analyzer.print_report()
