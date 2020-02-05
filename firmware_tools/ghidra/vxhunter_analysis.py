from vxhunter_core import *
from vxhunter_utility.function_analyzer import *
from vxhunter_utility.symbol import *
from vxhunter_utility.common import create_initialized_block
from ghidra.program.model.symbol import RefType, SourceType


class VxAnalyzer(object):
    def __init__(self, logger=None):
        self._vx_version = None
        self.report = []

        if logger is None:
            self.logger = logging.getLogger('target')
            self.logger.setLevel(logging.INFO)
            consolehandler = logging.StreamHandler()
            console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
            consolehandler.setFormatter(console_format)
            self.logger.addHandler(consolehandler)
        else:
            self.logger = logger

    def analyze_bss(self):
        self.report.append('{:-^60}'.format('analyze bss info'))
        self.logger.info("Start analyze bss info")
        target_function = getFunction("bzero")
        if not target_function:
            target_function = getFunction("_bzero")
        if target_function:
            parms_data = dump_call_parm_value(call_address=target_function.getEntryPoint(), search_functions=['sysStart',
                                                                                                              'usrInit',
                                                                                                              '_sysStart',
                                                                                                              '_usrInit',
                                                                                                              ])
            for call_addr in parms_data:
                call_parms = parms_data[call_addr]
                # print(call_parms)
                bss_start_address = call_parms['parms']['parm_1']['parm_value']
                self.report.append("bss_start_address: {}".format(hex(bss_start_address)))
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
        target_function = getFunction("loginUserAdd")
        if not target_function:
            target_function = getFunction("_loginUserAdd")
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
                target_function = getFunction(service_function)
                if not target_function:
                    target_function = getFunction("_{}".format(service_function))
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
        target_function = getFunction("symFindByName")

        if not target_function:
            target_function = getFunction("_symFindByName")

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

                        to_function = getFunction(searched_symbol_name)

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
                if not self._vx_version:
                    vx_version = askChoice("Choice", "Please choose VxWorks main Version ", ["5.x", "6.x"], "5.x")

                    if vx_version == u"5.x":
                        self._vx_version = 5

                    elif vx_version == u"6.x":
                        self._vx_version = 6
                        self.logger.error("VxHunter didn't support netpool analyze for VxWorks version 6.x")
                        self.report.append("VxHunter didn't support netpool analyze for VxWorks version 6.x")

                if self._vx_version == 5:
                    fix_netpool(net_dpool_addr, 5)

            except Exception as err:
                self.logger.error(err)

        self.report.append('{}\r\n'.format("-" * 60))

    def print_report(self):
        for line in self.report:
            print(line)

    def start_analyzer(self):
        self.analyze_bss()
        self.analyze_login_accouts()
        self.analyze_service()
        self.analyze_symbols()
        self.analyze_netpool()
        self.analyze_function_xref_by_symbol_get()


if __name__ == '__main__':
    analyzer = VxAnalyzer()
    analyzer.start_analyzer()
    analyzer.print_report()
