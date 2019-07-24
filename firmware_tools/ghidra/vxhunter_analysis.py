from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults
from ghidra.program.model.pcode import HighParam, PcodeOp, PcodeOpAST
from ghidra.program.model.address import GenericAddress
from ghidra.app.util.demangler import DemangledException
from ghidra.app.util.demangler.gnu import GnuDemangler
import logging
import time
import struct


endian = currentProgram.domainFile.getMetadata()[u'Endian']
if endian == u'Big':
    is_big_endian = True
else:
    is_big_endian = False


process_type = currentProgram.domainFile.getMetadata()[u'Processor']
if process_type.endswith(u'64'):
    process_is_64bit = True


demangler = GnuDemangler()
can_demangle = demangler.canDemangle(currentProgram)


def demangle_function_name(function_name):
    sym_demangled_name = function_name
    try:
        sym_demangled = demangler.demangle(function_name, True)

        if not sym_demangled:
            # some mangled function name didn't start with mangled prefix
            sym_demangled = demangler.demangle(function_name, False)

        if sym_demangled:
            sym_demangled_name = sym_demangled.getSignature(False)

    except DemangledException as err:
        # print("Got DemangledException: {}".format(err))
        return sym_demangled_name

    return sym_demangled_name


def is_address_in_current_program(address):
    for block in currentProgram.memory.blocks:
        if address.offset in range(block.getStart().offset,block.getEnd().offset):
            return True
    return False


def get_signed_value(data):
    pack_format = ""
    if is_big_endian:
        pack_format += ">"
    else:
        pack_format += "<"

    if process_is_64bit:
        pack_format += "L"
    else:
        pack_format += "I"

    data = struct.pack(pack_format.upper(), data.offset)
    signed_data = struct.unpack(pack_format.lower(), data)[0]

    return signed_data


class FlowNode(object):
    def __init__(self, var_node):
        """ Used to get VarNode value

        :param var_node:
        """
        self.var_node = var_node

    def get_value(self):
        """ Get VarNode value depend on it's type.

        :return:
        """
        if self.var_node.isAddress():
            return self.var_node.getAddress()
        elif self.var_node.isConstant():
            return self.var_node.getAddress()
        elif self.var_node.isUnique():
            return calc_pcode_op(self.var_node.getDef())
        elif self.var_node.isRegister():
            return calc_pcode_op(self.var_node.getDef())


def calc_pcode_op(pcode):
    # print("pcode: {}, type: {}".format(pcode, type(pcode)))
    if isinstance(pcode, PcodeOpAST):
        opcode = pcode.getOpcode()
        if opcode == PcodeOp.PTRSUB:
            var_node_1 = FlowNode(pcode.getInput(0))
            var_node_2 = FlowNode(pcode.getInput(1))
            value_1 = var_node_1.get_value()
            value_2 = var_node_2.get_value()
            if isinstance(value_1, GenericAddress) and isinstance(value_2, GenericAddress):
                return value_1.offset + value_2.offset
            else:
                return None

        elif opcode == PcodeOp.CAST:
            var_node_1 = FlowNode(pcode.getInput(0))
            value_1 = var_node_1.get_value()
            if isinstance(value_1, GenericAddress):
                return value_1.offset
            else:
                return None

        elif opcode == PcodeOp.PTRADD:
            var_node_0 = FlowNode(pcode.getInput(0))
            var_node_1 = FlowNode(pcode.getInput(1))
            var_node_2 = FlowNode(pcode.getInput(2))
            try:
                value_0_point = var_node_0.get_value()
                value_0 = toAddr(getInt(value_0_point))
                value_1 = var_node_1.get_value()
                value_2 = var_node_2.get_value()
                value_1 = get_signed_value(value_1.offset)
                # print("value_0: {}".format(value_0))
                # print("type(value_0): {}".format(type(value_0)))
                # print("value_1: {}".format(value_1))
                # print("type(value_1): {}".format(type(value_1)))
                # print("value_2: {}".format(value_2))
                # print("type(value_2): {}".format(type(value_2)))
                rsp = value_0.add(value_1)
                # print("rsp: {}".format(rsp))
                return rsp.offset
            except:
                # print("Got something wrong with calc PcodeOp.PTRADD ")
                return None

    else:
        return None


class ParmTrace(object):

    def __init__(self, function, call_address, timeout=30, logger=None):
        """

        :param function: Ghidra function object.
        :param call_address: Ghidra Address object.
        :param timeout: timeout for decompile.
        :param logger: logger.
        """
        self.function = function
        self.call_address = call_address
        self.timeout = timeout
        if logger is None:
            self.logger = logging.getLogger('target')
            self.logger.setLevel(logging.INFO)
            consolehandler = logging.StreamHandler()
            console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
            consolehandler.setFormatter(console_format)
            self.logger.addHandler(consolehandler)
        else:
            self.logger = logger

    def get_hfunction(self, function):
        """

        :param function:
        :return:
        """
        decomplib = DecompInterface()
        decomplib.openProgram(currentProgram)
        timeout = self.timeout
        dRes = decomplib.decompileFunction(function, timeout, getMonitor())
        hfunction = dRes.getHighFunction()
        return hfunction

    def get_function_pcode(self, hfunction):
        """Get pcode from hfunction.

        :param hfunction:
        :return:
        """
        ops = hfunction.getPcodeOps()
        return ops

    def print_pcodes(self, ops):
        while ops.hasNext():
            pcodeOpAST = ops.next()
            print(pcodeOpAST)
            opcode = pcodeOpAST.getOpcode()
            print("Opcode: {}".format(opcode))
            if opcode == PcodeOp.CALL:
                print("We found Call at 0x{}".format(pcodeOpAST.getInput(0).PCAddress))
                call_addr = pcodeOpAST.getInput(0).getAddress()
                print("Calling {}(0x{}) ".format(getFunctionAt(call_addr), call_addr))
                inputs = pcodeOpAST.getInputs()
                for i in range(len(inputs)):
                    parm = inputs[i]
                    print("parm{}: {}".format(i, parm))

    def analysis_call(self, ops):
        parms = {}
        paths = []

        while ops.hasNext():
            pcodeOpAST = ops.next()
            opcode = pcodeOpAST.getOpcode()
            if opcode == PcodeOp.CALL:
                # TODO: Need handle call_addr calc method.
                call_addr = pcodeOpAST.getInput(0).PCAddress
                if self.call_address == call_addr:
                    self.logger.debug("We found target call at 0x{} in function {}(0x{})".format(
                        pcodeOpAST.getInput(0).PCAddress, self.function.name, hex(self.function.entryPoint.offset)))
                    target_call_addr = pcodeOpAST.getInput(0).getAddress()
                    self.logger.debug("Calling {}(0x{}) ".format(getFunctionAt(target_call_addr), target_call_addr))
                    inputs = pcodeOpAST.getInputs()
                    for i in range(len(inputs))[1:]:
                        parm = inputs[i]
                        self.logger.debug("parm{}: {}".format(i, parm))
                        parm_node = FlowNode(parm)
                        parm_value = parm_node.get_value()
                        if isinstance(parm_value, GenericAddress):
                            parm_value = parm_value.offset
                        parms[i] = parm_value
                        if parm_value:
                            self.logger.debug("parm{} value: {}".format(i, hex(parm_value)))
                    return parms

            elif opcode == PcodeOp.CALLIND:
                self.logger.debug("In PcodeOp.CALLIND")
                call_addr = pcodeOpAST.getInput(0).PCAddress
                self.logger.debug("call_addr: {}".format(call_addr))
                self.logger.debug("self.call_address.offset: {}".format(self.call_address))
                if self.call_address == call_addr:
                    self.logger.debug("We found target call at 0x{} in function {}(0x{})".format(
                        pcodeOpAST.getInput(0).PCAddress, self.function.name, hex(self.function.entryPoint.offset)))
                    # target_call_addr = pcodeOpAST.getInput(0).getAddress()
                    target_call_addr = FlowNode(pcodeOpAST.getInput(0)).get_value()
                    target_call_addr = toAddr(getInt(toAddr(target_call_addr)))
                    self.logger.debug("Calling {}(0x{}) ".format(getFunctionAt(target_call_addr), target_call_addr))
                    inputs = pcodeOpAST.getInputs()
                    for i in range(len(inputs))[1:]:
                        parm = inputs[i]
                        self.logger.debug("parm{}: {}".format(i, parm))
                        parm_node = FlowNode(parm)
                        parm_value = parm_node.get_value()
                        if isinstance(parm_value, GenericAddress):
                            parm_value = parm_value.offset
                        parms[i] = parm_value
                        if parm_value:
                            # print("type:{}".format(type(parm_node.get_value())))
                            self.logger.debug("parm{} value: {}".format(i, hex(parm_value)))
                        # self.process_varnode(parm)
                    return parms


def get_call_parm_value(call_address):
    target_function = getFunctionAt(call_address)
    parms_data = {}
    cache_data = {}
    if target_function:
        function_name = target_function.name
        target_references = getReferencesTo(target_function.getEntryPoint())
        for target_reference in target_references:
            # Filter reference type
            reference_type = target_reference.getReferenceType()
            # print("reference_type: {}".format(reference_type))
            # print("isJump: {}".format(reference_type.isJump()))
            # print("isCall: {}".format(reference_type.isCall()))
            # if reference_type.isJump() is False and reference_type.isCall() is False:
            if not reference_type.isCall():
                # print("skip!")
                continue

            call_addr = target_reference.getFromAddress()
            # print("call_addr: {}".format(call_addr))
            function = getFunctionContaining(call_addr)
            # print("function: {}".format(function))
            if not function:
                continue

            target = ParmTrace(function=function, call_address=call_addr)
            function_address = function.getEntryPoint().offset
            if function_address in cache_data:
                hfunction = cache_data[function_address]['hfunction']
            else:
                hfunction = target.get_hfunction(function)
                if not hfunction:
                    # print("Can't get hfunction")
                    continue
                else:
                    cache_data[function_address] = {'hfunction': hfunction}

            ops = target.get_function_pcode(hfunction)
            # print("-" * 30)
            parms = target.analysis_call(ops)
            demangled_function_name = demangle_function_name(function.name)
            if function.name == demangle_function_name(function.name):
                refrence_function_name = function.name
            else:
                refrence_function_name = "{}({})".format(demangled_function_name, function.name)

            parms_data[call_addr.offset] = {
                'call_addr': call_addr.offset,
                'refrence_function_addr': function.getEntryPoint().offset,
                'refrence_function_name': refrence_function_name,
                'parms': {}
            }
            trace_data = parms_data[call_addr.offset]
            # print(trace_data)

            if not parms:
                continue

            for i in parms:
                # print("parms{}: {}".format(i, parms[i]))
                parm_value = parms[i]
                # print("parm_value: {}".format(parm_value))
                parm_data = None
                if parm_value:
                    # print("IN")
                    if is_address_in_current_program(toAddr(parm_value)):
                        # print("IN2")
                        if getDataAt(toAddr(parm_value)):
                            parm_data = getDataAt(toAddr(parm_value))
                        elif getInstructionAt(toAddr(parm_value)):
                            parm_data = getFunctionAt(toAddr(parm_value))

                trace_data['parms']["parm_{}".format(i)] = {'parm_value': parm_value,
                                                            'parm_data': parm_data
                                                            }

        return parms_data


def analyze_login_accouts():
    print('{:-^60}'.format('analyze loginUserAdd function'))
    target_function = getFunction("loginUserAdd")
    if target_function:
        parms_data = get_call_parm_value(target_function.getEntryPoint())
        for call_addr in parms_data:
            call_parms = parms_data[call_addr]
            parm_data_string = ""
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
            # print("parm_data_string: {}".format(parm_data_string))
            print("{}({}) at {:#010x} in {}({:#010x})".format(target_function.name, parm_data_string,
                                                              call_parms['call_addr'],
                                                              call_parms['refrence_function_name'],
                                                              call_parms['refrence_function_addr']
                                                              ))
    else:
        print("Can't find loginUserAdd function in firmware")

    print('-' * 60)


if __name__ == '__main__':
    analyze_login_accouts()