#Trace parameters of a function
#@author Wenzhe Zhu
#@category VxWorks
#@keybinding
#@menupath
#@toolbar
# coding=utf-8
import logging
import time
from vxhunter_core import VxTarget
from vxhunter_utility.common import *
from vxhunter_utility.symbol import add_symbol, fix_symbol_table_structs
from ghidra.util.task import TaskMonitor

# Logger setup
logger = get_logger(__name__)
report = []


# For https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
try:
    from ghidra_builtins import *

except Exception as err:
    pass


def init_firmware():
    # Init Timer
    timer = Timer()
    try:
        vx_version = askChoice("Choice", "Please choose VxWorks main Version ", ["5.x", "6.x"], "5.x")
        if vx_version == u"5.x":
            vx_version = 5

        elif vx_version == u"6.x":
            vx_version = 6

        if vx_version:
            firmware_path = currentProgram.domainFile.getMetadata()['Executable Location']
            firmware = open(firmware_path, 'rb').read()
            # Start timer
            timer.start_timer()
            target = VxTarget(firmware=firmware, vx_version=vx_version)
            target.quick_test()
            if target.load_address is None:
                logger.debug("Load address is None. Running find_loading_address.")
                target.find_loading_address()

            if target.load_address:
                load_address_time = timer.get_timer()
                logger.info("Analyze Load Address takes {:.3f} seconds".format(load_address_time))
                load_address = target.load_address

                # Rebase_image
                timer.reset()
                target_block = currentProgram.memory.blocks[0]
                address = toAddr(load_address)
                logger.debug("Rebasing. target_block: {}; load_address: {}".format(target_block, address))
                currentProgram.memory.moveBlock(target_block, address, TaskMonitor.DUMMY)
                rebase_time = timer.get_timer()
                logger.info("Rebase image takes {:.3f} seconds".format(rebase_time))

                # Create symbol table structs
                timer.reset()
                logger.debug("Creating symbol table.")
                symbol_table_start = target.symbol_table_start + target.load_address
                symbol_table_end = target.symbol_table_end + target.load_address
                fix_symbol_table_structs(symbol_table_start, symbol_table_end, vx_version)
                fix_symbol_table_time = timer.get_timer()
                logger.info("Creating symbol table takes {:.3f} seconds".format(fix_symbol_table_time))

                # Load symbols
                timer.reset()
                function_manager = currentProgram.getFunctionManager()
                functions_count_before = function_manager.getFunctionCount()
                report.append('{:-^60}'.format('Analyze symbol table'))
                report.append("Functions count: {}(Before analyze) ".format(functions_count_before))
                symbols = target.get_symbols()

                for symbol in symbols:
                    try:
                        symbol_name = symbol["symbol_name"]
                        symbol_name_addr = symbol["symbol_name_addr"]
                        symbol_dest_addr = symbol["symbol_dest_addr"]
                        symbol_flag = symbol["symbol_flag"]
                        add_symbol(symbol_name, symbol_name_addr, symbol_dest_addr, symbol_flag)

                    except Exception as err:
                        logger.error("add_symbol failed: {}".format(err))
                        continue
                logger.info("Waiting for pending analysis to complete...")
                load_symbols_time = timer.get_timer()
                logger.info("Load symbols takes {:.3f} seconds".format(load_symbols_time))
                timer.reset()
                analyzeAll(currentProgram)
                functions_count_after = function_manager.getFunctionCount()
                ghidra_analyze_all_time = timer.get_timer()
                logger.info("Ghidra analyzer all takes {:.3f} seconds".format(ghidra_analyze_all_time))
                report.append("Functions count: {}(After analyze) ".format(functions_count_after))
                report.append("VxHunter found {} new functions".format(functions_count_after - functions_count_before))
                report.append('{}\r\n'.format("-" * 60))

                # Add timer report
                report.append('{:-^60}'.format('VxHunter timer'))
                report.append("Analyze Load Address takes {:.3f} seconds".format(load_address_time))
                report.append("Rebase image takes {:.3f} seconds".format(rebase_time))
                report.append("Creating symbol table takes {:.3f} seconds".format(fix_symbol_table_time))
                report.append("Load symbols takes {:.3f} seconds".format(load_symbols_time))
                report.append("Ghidra analyzer all takes {:.3f} seconds".format(ghidra_analyze_all_time))
                report.append('{}\r\n'.format("-" * 60))
                for line in report:
                    print(line)

            else:
                popup("Can't find symbols in binary")

    except Exception as err:
        print(err)


if __name__ == '__main__':
    init_firmware()
