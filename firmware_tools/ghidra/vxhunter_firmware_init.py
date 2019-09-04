# coding=utf-8
from vxhunter_core import *
from ghidra.util.task import TaskMonitor
from ghidra.program.model.symbol.SourceType import USER_DEFINED
from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.app.util.demangler import DemangledException
from ghidra.app.util.demangler.gnu import GnuDemangler
from ghidra.program.model.listing.CodeUnit import PLATE_COMMENT
from ghidra.program.model.data import DataType


try:
    vx_version = askChoice("Choice", "Please choose VxWorks main Version ", ["5.x", "6.x"], "5.x")
    if vx_version == u"5.x":
        vx_version = 5

    elif vx_version == u"6.x":
        vx_version = 6

    if vx_version:
        firmware_path = currentProgram.domainFile.getMetadata()['Executable Location']
        firmware = open(firmware_path, 'rb').read()
        target = VxTarget(firmware=firmware, vx_version=vx_version)
        # target.logger.setLevel(logging.DEBUG)
        target.quick_test()
        if target.load_address is None:
            target.find_loading_address()
        demangler = GnuDemangler()
        listing = currentProgram.getListing()
        can_demangle = demangler.canDemangle(currentProgram)
        if target.load_address:
            ghidra_sym_tbl = currentProgram.getSymbolTable()
            load_address = target.load_address
            target.logger.info("load_address:%s" % hex(load_address))

            # Rebase_image
            target_block = currentProgram.memory.blocks[0]
            print("target_block: %s" % target_block)
            address = toAddr(load_address)
            print("address: %s" % address)
            currentProgram.memory.moveBlock(target_block, address, TaskMonitor.DUMMY)

            # Rename functions
            symbol_table_start = toAddr(target.symbol_table_start + target.load_address)
            symbol_table_end = toAddr(target.symbol_table_end + target.load_address)
            symbol_interval = 16
            if vx_version == 6:
                symbol_interval = 20
            ea = symbol_table_start
            while ea < symbol_table_end:
                symbol_name_string = None
                offset = 4
                symbol_flag = getInt(ea.add(symbol_interval - 4))
                symbol_name_address = toAddr(getInt(ea.add(offset)))
                symbol_dest_address = toAddr(getInt(ea.add(offset + 4)))
                print("symbol_address: %s" % ea)
                print("symbol_flag: %s" % symbol_flag)
                print("symbol_name_address: %s" % symbol_name_address)
                print("symbol_dest_address: %s" % symbol_dest_address)
                if not symbol_dest_address:
                    ea = ea.add(symbol_interval)
                    continue

                # Get symbol_name
                if getDataAt(symbol_name_address):
                    print("removeDataAt: %s" % symbol_name_address)
                    removeDataAt(symbol_name_address)
                if getInstructionAt(symbol_dest_address):
                    print("removeInstructionAt: %s" % symbol_dest_address)
                    removeInstructionAt(symbol_dest_address)

                try:
                    symbol_name_string = createAsciiString(symbol_name_address).getValue()
                    print("symbol_name_string: %s" % symbol_name_string)
                except CodeUnitInsertionException as err:
                    # Todo: Need find a way to get subString
                    print("Got CodeUnitInsertionException: {}".format(err))
                    ea = ea.add(symbol_interval)
                    continue

                except:
                    ea = ea.add(symbol_interval)
                    continue

                try:
                    # Demangle symName
                    sym_demangled_name = None
                    if can_demangle:
                        try:
                            sym_demangled = demangler.demangle(symbol_name_string, True)

                            if not sym_demangled:
                                # some mangled function name didn't start with mangled prefix
                                sym_demangled = demangler.demangle(symbol_name_string, False)

                            if sym_demangled:
                                sym_demangled_name = sym_demangled.getSignature(False)

                        except DemangledException as err:
                            # print("Got DemangledException: {}".format(err))
                            sym_demangled_name = None

                        if sym_demangled_name:
                            print("sym_demangled_name: %s" % sym_demangled_name)

                    if symbol_name_string and (symbol_flag in need_create_function):
                        print("Start disassemble function %s at address %s" % (symbol_name_string,
                                                                               symbol_dest_address.toString()))
                        disassemble(symbol_dest_address)
                        # TODO: find out why createFunction didn't set the function name.
                        function = createFunction(symbol_dest_address, symbol_name_string)
                        # use createLabel to rename function for now.
                        createLabel(symbol_dest_address, symbol_name_string, True)
                        if function and sym_demangled_name:
                            # Add demangled string to comment
                            codeUnit = listing.getCodeUnitAt(symbol_dest_address)
                            codeUnit.setComment(codeUnit.PLATE_COMMENT, sym_demangled_name)
                            # Rename function
                            function_return, function_name, function_parameters = demangle_function(sym_demangled_name)
                            print("Demangled function name is: %s" % function_name)
                            print("Demangled function return is: %s" % function_return)
                            print("Demangled function parameters is: %s" % function_parameters)
                            function.setName(function_name, USER_DEFINED)
                            # Todo: Add parameters later
                    else:
                        createLabel(symbol_dest_address, symbol_name_string, True)
                        if sym_demangled_name:
                            codeUnit = listing.getCodeUnitAt(symbol_dest_address)
                            codeUnit.setComment(codeUnit.PLATE_COMMENT, sym_demangled_name)

                except Exception as err:
                    print("Create function Failed: %s" % err)

                print("keep going!")
                ea = ea.add(symbol_interval)

        else:
            popup("Can't find symbols in binary")

except Exception as err:
    print(err)
