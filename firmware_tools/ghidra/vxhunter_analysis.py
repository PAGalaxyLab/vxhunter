from vxhunter_core import *
from vxhunter_utility.function_analyzer import *
from vxhunter_utility.symbol import *
from vxhunter_utility.common import create_initialized_block
from ghidra.program.model.symbol import RefType, SourceType


class VxAnalyzer(object):
    def __init__(self, logger=None):
        self._vx_version = None

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
        print('{:-^60}'.format('analyze bss info'))
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
                print("bss_start_address: {}".format(hex(bss_start_address)))
                bss_length = call_parms['parms']['parm_2']['parm_value']
                if not bss_length:
                    print("Can't calculate bss length.")
                    return
                print("bss_end_address: {}".format(hex(bss_start_address + bss_length - 1)))
                print("bss_length: {}".format(hex(bss_length)))
                if not is_address_in_current_program(toAddr(bss_start_address)):
                    print("bss block not in current program, adding...")
                    if create_initialized_block(block_name=".bss", start_address=toAddr(bss_start_address),
                                                length=bss_length):
                        print("bss block created")
                    else:
                        print("Can't create bss block, you can create it manually")

        else:
            print("Can't find bzero function in firmware")

        print('{}\r\n'.format("-" * 60))

    def analyze_login_accouts(self):
        hard_coded_accounts = {}
        print("{:-^60}".format("analyze loginUserAdd function"))
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
            print("Can't find loginUserAdd function in firmware")

        print("Found {} hard coded accounts".format(len(hard_coded_accounts)))
        for account in hard_coded_accounts:
            print("user_name: {}, pass_hash: {}, added at address: {}".format(
                hard_coded_accounts[account]['user_name'],
                hard_coded_accounts[account]['pass_hash'],
                hex(account.offset)
            ))

        print('{}\r\n'.format("-" * 60))

    def analyze_service(self):
        service_status = {}
        print('{:-^60}'.format('analyze services'))
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
            print('{}: {}'.format(service[0], service[1]))
        print('{}\r\n'.format("-" * 60))

    def analyze_symbols(self):
        print('{:-^60}'.format('analyze symbols using sysSymTbl'))
        function_manager = currentProgram.getFunctionManager()
        functions_count_before = function_manager.getFunctionCount()
        sys_sym_tbl = get_symbol('sysSymTbl')

        if not sys_sym_tbl:
            print('{}\r\n'.format("-" * 60))
            return

        if not is_address_in_current_program(sys_sym_tbl.getAddress()):
            print('{}\r\n'.format("-" * 60))
            return

        sys_sym_addr = toAddr(getInt(sys_sym_tbl.getAddress()))

        if not is_address_in_current_program(sys_sym_addr):
            print("sys_sym_addr({:#010x}) is not in current_program".format(sys_sym_addr.getOffset()))
            print('{}\r\n'.format("-" * 60))
            return

        if sys_sym_addr.getOffset() == 0:
            print('{}\r\n'.format("-" * 60))
            return

        else:
            try:
                if not self._vx_version:
                    vx_version = askChoice("Choice", "Please choose VxWorks main Version ", ["5.x", "6.x"], "5.x")
                    if vx_version == u"5.x":
                        self._vx_version = 5

                    elif vx_version == u"6.x":
                        self._vx_version = 6
                        print("VxHunter didn't support symbols analyze for VxWorks version 6.x")

                if self._vx_version == 5:
                    print("Functions count: {}(Before analyze) ".format(functions_count_before))
                    # for i in range(vx_5_sys_symtab.getLength()):
                    #     removeDataAt(sys_sym_addr.add(i))
                    create_struct(sys_sym_addr, vx_5_sys_symtab)
                    hash_tbl_addr = toAddr(getInt(sys_sym_addr.add(0x04)))
                    # for i in range(vx_5_hash_tbl.getLength()):
                    #     removeDataAt(hash_tbl_addr.add(i))
                    create_struct(hash_tbl_addr, vx_5_hash_tbl)
                    hash_tbl_length = getInt(hash_tbl_addr.add(0x04))
                    hash_tbl_array_addr = toAddr(getInt(hash_tbl_addr.add(0x14)))
                    hash_tbl_array_data_type = ArrayDataType(vx_5_sl_list, hash_tbl_length, vx_5_sl_list.getLength())
                    create_struct(hash_tbl_array_addr, hash_tbl_array_data_type)
                    for i in range(0, hash_tbl_length):
                        list_head = toAddr(getInt(hash_tbl_array_addr.add(i * 8)))
                        list_tail = toAddr(getInt(hash_tbl_array_addr.add((i * 8) + 0x04)))
                        if is_address_in_current_program(list_head) and is_address_in_current_program(list_tail):
                            fix_symbol_by_chains(list_head, list_tail, vx_version)
                    functions_count_after = function_manager.getFunctionCount()
                    print("Functions count: {}(After analyze) ".format(functions_count_after))
                    print("VxHunter found {} new functions".format(functions_count_after - functions_count_before))
            except Exception as err:
                print(err)

        print('{}\r\n'.format("-" * 60))

    def analyze_function_xref_by_symbol_get(self):
        print('{:-^60}'.format('analyze symFindByName function call'))

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
                        print("Found symFindByName({}) call at {:#010x}".format(searched_symbol_name,
                                                                          call_parms['call_addr'].offset))

                        to_function = getFunction(searched_symbol_name)

                        if to_function:
                            ref_to = to_function.getEntryPoint()
                            ref_from = call_parms['call_addr']
                            currentReferenceManager.addMemoryReference(ref_from, ref_to, RefType.READ,
                                                                       SourceType.USER_DEFINED, 0)
                            print("Add Reference for {}( {:#010x} ) function call at {:#010x} in {}( {:#010x} )".format(
                                to_function,
                                ref_to.offset,
                                call_parms['call_addr'].offset,
                                call_parms['refrence_function_name'],
                                call_parms['refrence_function_addr'].offset
                            )
                            )

                        else:
                            print("Can't find {} symbol in firmware".format(searched_symbol_name))

                        logger.debug("{}({}) at {:#010x} in {}({:#010x})".format(target_function.name, searched_symbol_name,
                                                                                 call_parms['call_addr'].offset,
                                                                                 call_parms['refrence_function_name'],
                                                                                 call_parms['refrence_function_addr'].offset
                                                                                 ))
                except Exception as err:
                    print(err)

        else:
            print("Can't find {} function in firmware".format(target_function))

        print('{}\r\n'.format("-" * 60))

    def analyze_netpool(self):
        print('{:-^60}'.format('analyze netpool'))
        pools = ["_pNetDpool", "_pNetSysPool"]
        for pool in pools:
            print('{:-^20}'.format(pool))
            net_dpool = get_symbol(pool)
            net_dpool_addr = toAddr(getInt(net_dpool.getAddress()))

            if not is_address_in_current_program(net_dpool_addr):
                print("{}({:#010x}) is not in current_program".format(pool, net_dpool_addr.getOffset()))

            elif net_dpool_addr.getOffset() == 0:
                pass

            print("Found {} at {:#010x}".format(pool, net_dpool_addr.getOffset()))

            try:
                if not self._vx_version:
                    vx_version = askChoice("Choice", "Please choose VxWorks main Version ", ["5.x", "6.x"], "5.x")

                    if vx_version == u"5.x":
                        self._vx_version = 5

                    elif vx_version == u"6.x":
                        self._vx_version = 6
                        print("VxHunter didn't support netpool analyze for VxWorks version 6.x")

                if self._vx_version == 5:
                    fix_netpool(net_dpool_addr, 5)

            except Exception as err:
                print(err)

        print('{}\r\n'.format("-" * 60))

    def start_analyzer(self):
        self.analyze_bss()
        self.analyze_login_accouts()
        self.analyze_service()
        self.analyze_symbols()
        self.analyze_function_xref_by_symbol_get()
        self.analyze_netpool()


if __name__ == '__main__':
    analyzer = VxAnalyzer()
    analyzer.start_analyzer()
