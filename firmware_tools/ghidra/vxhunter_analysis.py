from vxhunter_core import *
from vxhunter_utility.function_analyzer import *
from vxhunter_utility.symbol import *
from ghidra.program.model.symbol import RefType, SourceType


def analyze_bss():
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
                print("bss block not in current program, you should add it manually")
                # TODO: automatic create bss block, after find out how createBlock function work.
                # createBlock("bss", toAddr(bss_start_address), bss_length)

    else:
        print("Can't find bzero function in firmware")

    print('{}\r\n'.format("-" * 60))


def analyze_login_accouts():
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


def analyze_service():
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


def add_symbol(symbol_name, symbol_name_address, symbol_address, symbol_type):
    symbol_name_address = toAddr(symbol_name_address)
    symbol_address = toAddr(symbol_address)

    # Get symbol_name
    if getDataAt(symbol_name_address):
        logger.debug("removeDataAt: %s" % symbol_name_address)
        removeDataAt(symbol_name_address)

    if getInstructionAt(symbol_address):
        logger.debug("removeInstructionAt: %s" % symbol_address)
        removeInstructionAt(symbol_address)

    try:
        symbol_name_string = createAsciiString(symbol_name_address).getValue()
        logger.debug("symbol_name_string: %s" % symbol_name_string)

    except CodeUnitInsertionException as err:
        logger.debug("Got CodeUnitInsertionException: {}".format(err))
        symbol_name_string = symbol_name

    except:
        return

    # Demangle symName
    try:
        # Demangle symName
        sym_demangled_name = None
        if can_demangle:
            try:
                sym_demangled = demangler.demangle(symbol_name_string, True)

                if not sym_demangled:
                    # some mangled function name didn't start with mangled prefix
                    sym_demangled = demangler.demangle(symbol_name_string, False)

                if not sym_demangled:
                    # Temp fix to handle _ prefix function name by remove _ prefix before demangle
                    sym_demangled = demangler.demangle(symbol_name_string[1:], False)

                if sym_demangled:
                    sym_demangled_name = sym_demangled.getSignature(False)

            except DemangledException as err:
                sym_demangled_name = None

            if sym_demangled_name:
                logger.debug("sym_demangled_name: %s" % sym_demangled_name)

        if symbol_name_string and (symbol_type in need_create_function):
            logger.debug("Start disassemble function %s at address %s" % (symbol_name_string, symbol_address.toString()))
            disassemble(symbol_address)
            # TODO: find out why createFunction didn't set the function name.
            function = createFunction(symbol_address, symbol_name_string)
            # use createLabel to rename function for now.
            createLabel(symbol_address, symbol_name_string, True)
            if function and sym_demangled_name:
                # Add demangled string to comment
                codeUnit = listing.getCodeUnitAt(symbol_address)
                codeUnit.setComment(codeUnit.PLATE_COMMENT, sym_demangled_name)
                # Rename function
                function_return, function_name, function_parameters = demangle_function(sym_demangled_name)
                logger.debug("Demangled function name is: %s" % function_name)
                logger.debug("Demangled function return is: %s" % function_return)
                logger.debug("Demangled function parameters is: %s" % function_parameters)
                function.setName(function_name, SourceType.USER_DEFINED)
                # Todo: Add parameters later
        else:
            createLabel(symbol_address, symbol_name_string, True)
            if sym_demangled_name:
                codeUnit = listing.getCodeUnitAt(symbol_address)
                codeUnit.setComment(codeUnit.PLATE_COMMENT, sym_demangled_name)

    except Exception as err:
        logger.debug("Create function Failed: %s" % err)

    except:
        logger.debug("Create function Failed: Java error")


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

        for i in range(dt.getLength()):
            removeDataAt(ea.add(i))

        createData(ea, dt)
        # Using symbol_address as default symbol_name.
        symbol_name = "0x{:08X}".format(symbol_dest_address)
        add_symbol(symbol_name, symbol_name_address, symbol_dest_address, symbol_type)

        if getInt(ea) == 0 or ea == tail:
            break

        ea = prev_symbol_addr

    return


def analyze_symbols():
    print('{:-^60}'.format('analyze symbols using sysSymTbl'))
    function_manager = currentProgram.getFunctionManager()
    functions_count_before = function_manager.getFunctionCount()
    sys_sym_tbl = getSymbol('sysSymTbl', currentProgram.getGlobalNamespace())
    if not sys_sym_tbl:
        sys_sym_tbl = getSymbol('_sysSymTbl', currentProgram.getGlobalNamespace())

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
            vx_version = askChoice("Choice", "Please choose VxWorks main Version ", ["5.x", "6.x"], "5.x")
            if vx_version == u"5.x":
                vx_version = 5

            elif vx_version == u"6.x":
                vx_version = 6
                print("VxHunter didn't support symbols analyze for VxWorks version 6.x")

            if vx_version == 5:
                print("Functions count: {}(Before analyze) ".format(functions_count_before))
                for i in range(vx_5_sys_symtab.getLength()):
                    removeDataAt(sys_sym_addr.add(i))
                createData(sys_sym_addr, vx_5_sys_symtab)
                hash_tbl_addr = toAddr(getInt(sys_sym_addr.add(0x04)))
                for i in range(vx_5_hash_tbl.getLength()):
                    removeDataAt(hash_tbl_addr.add(i))
                createData(hash_tbl_addr, vx_5_hash_tbl)
                hash_tbl_length = getInt(hash_tbl_addr.add(0x04))
                hash_tbl_array_addr = toAddr(getInt(hash_tbl_addr.add(0x14)))
                hash_tbl_array_data_type = ArrayDataType(vx_5_sl_list, hash_tbl_length, vx_5_sl_list.getLength())
                for i in range(hash_tbl_array_data_type.getLength()):
                    removeDataAt(hash_tbl_array_addr.add(i))
                createData(hash_tbl_array_addr, hash_tbl_array_data_type)
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


def analyze_function_xref_by_symbol_get():
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


if __name__ == '__main__':
    analyze_bss()
    analyze_login_accouts()
    analyze_service()
    analyze_symbols()
    analyze_function_xref_by_symbol_get()
