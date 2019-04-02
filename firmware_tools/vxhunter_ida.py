# coding=utf-8
import idc
import idaapi
from vx_target import VxTarget, need_create_function


# --------------------------------------------------------------------------
# Plugin
# --------------------------------------------------------------------------
class AutoFixIDBForm(idaapi.Form):
    def __init__(self):
        self.invert = False
        self.vx_version = 5
        super(AutoFixIDBForm, self).__init__(
            r"""BUTTON YES* Start analyze

VxHunter Auto Fix IDB will fix IDB with VxWorks symbol table.

Please choose VxWorks main version
{FormChangeCb}
<VxWorks Main Version     :{c_vxversion}>
            """, {
                'FormChangeCb': self.FormChangeCb(self.OnFormChange),
                'c_vxversion': self.DropdownListControl(
                    items=("5", "6"),
                    readonly=True,
                    selval=0),

            }
        )

        self.Compile()

    def OnFormChange(self, fid):
        if fid == -2:
            self.vx_version = (5, 6)[self.GetControlValue(self.c_vxversion)]
            return 1


class FixCodeForm(idaapi.Form):
    def __init__(self):
        self.invert = False
        self.start_address = 0
        self.end_address = 0
        super(FixCodeForm, self).__init__(
            r"""BUTTON YES* Fix Code from image

VxHunter fix code will make all data as code from start_address to end_address. 

Please input start address and end address
{FormChangeCb}
<Start address     :{c_StartAddress}>
<End address     :{c_EndAddress}>
            """, {
                'FormChangeCb': self.FormChangeCb(self.OnFormChange),
                'c_StartAddress': self.NumericInput(value=self.start_address, swidth=40, tp=self.FT_ADDR),
                'c_EndAddress': self.NumericInput(value=self.end_address, swidth=40, tp=self.FT_ADDR),
            }
        )
        self.Compile()

    def OnFormChange(self, fid):
        if fid == -2:
            self.start_address = self.GetControlValue(self.c_StartAddress)
            self.end_address = self.GetControlValue(self.c_EndAddress)
            return 1


class FixAsciiForm(idaapi.Form):
    def __init__(self):
        self.invert = False
        self.string_address = 0
        super(FixAsciiForm, self).__init__(
            r"""BUTTON YES* Fix Code from image

VxHunter fix ascii string. 

Please input string table start address.
{FormChangeCb}
<String Address     :{c_Address}>
            """, {
                'FormChangeCb': self.FormChangeCb(self.OnFormChange),
                'c_Address': self.NumericInput(value=self.string_address, swidth=40, tp=self.FT_ADDR),
            }
        )
        self.Compile()

    def OnFormChange(self, fid):
        if fid == -2:
            self.string_address = self.GetControlValue(self.c_Address)
            return 1


class VxHunter_Plugin_t(idaapi.plugin_t):
    comment = "VxHunter plugin for IDA Pro"
    help = ""
    wanted_name = "VxHunter"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        # register popup menu handlers
        try:
            # Register Auto Fix IDB handler
            VxHunterMCFixIDB.register(self, "Auto Fix IDB With symbol table")
            # Register Fix Code handler
            VxHunterMCFixCode.register(self, "Fix Code from start address to end address")
            # Register Fix Ascii handler
            VxHunterMCFixAscii.register(self, "Fix Ascii string table with giving address")

        except Exception as err:
            print("Got Error!!!: %s" % err)

        # setup popup menu
        if idaapi.IDA_SDK_VERSION >= 700:
            # Add menu IDA >= 7.0
            idaapi.attach_action_to_menu("Edit/VxHunter/", VxHunterMCFixIDB.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu("Edit/VxHunter/", VxHunterMCFixCode.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu("Edit/VxHunter/", VxHunterMCFixAscii.get_name(), idaapi.SETMENU_APP)
        else:
            # add Vxhunter menu
            menu = idaapi.add_menu_item("Edit/VxHunter/", "Auto Fix IDB1", "", 1, self.handler_auto_fix_idb, None)
            if menu is not None:
                pass

        print("=" * 80)
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    # null handler
    def menu_null(self):
        pass

    def handler_auto_fix_idb(self):
        form = AutoFixIDBForm()
        ok = form.Execute()
        if ok == 1:
            vx_version = int(form.vx_version)
            print("vx_version:%s" % vx_version)
            firmware_path = idaapi.get_input_file_path()
            firmware = open(firmware_path).read()
            target = VxTarget(firmware=firmware, vx_version=vx_version)
            # target.logger.setLevel(logging.DEBUG)
            target.quick_test()

            if target.load_address:
                print("Load Address is:%s" % target.load_address)
            else:
                target.find_loading_address()
                if target.load_address:
                    print("Load Address is:%s" % target.load_address)
            if not target.load_address:
                return
            symbol_table_start = target.symbol_table_start
            symbol_table_end = target.symbol_table_end
            load_address = target.load_address
            self.fix_vxworks_idb(load_address, vx_version, symbol_table_start, symbol_table_end)
        form.Free()

    def handler_fix_code(self):
        form = FixCodeForm()
        ok = form.Execute()
        if ok == 1:
            start_address = int(form.start_address)
            end_address = int(form.end_address)
            self.fix_code(start_address, end_address)
        form.Free()

    def handler_fix_ascii(self):
        form = FixAsciiForm()
        ok = form.Execute()
        if ok == 1:
            string_address = int(form.string_address)
            self.fix_ascii(string_address)

        form.Free()

    @staticmethod
    def fix_vxworks_idb(load_address, vx_version, symbol_table_start, symbol_table_end):
        current_image_base = idaapi.get_imagebase()
        symbol_interval = 16
        if vx_version == 6:
            symbol_interval = 20
        symbol_table_start += load_address
        symbol_table_end += load_address
        ea = symbol_table_start
        shift_address = load_address - current_image_base
        while shift_address >= 0x70000000:
            idaapi.rebase_program(0x70000000, 0x0008)
            shift_address -= 0x70000000
        idaapi.rebase_program(shift_address, 0x0008)
        while ea < symbol_table_end:
            # for VxWorks 6 unknown symbol format
            if idc.Byte(ea + symbol_table_end - 2) == 3:
                ea += symbol_interval
                continue
            offset = 4
            if idaapi.IDA_SDK_VERSION >= 700:
                idc.create_strlit(idc.Dword(ea + offset), idc.BADADDR)
            else:
                idc.MakeStr(idc.Dword(ea + offset), idc.BADADDR)
            sName = idc.GetString(idc.Dword(ea + offset), -1, idc.ASCSTR_C)
            print("Found %s in symbol table" % sName)
            if sName:
                sName_dst = idc.Dword(ea + offset + 4)
                if vx_version == 6:
                    sName_type = idc.Dword(ea + offset + 12)
                else:
                    sName_type = idc.Dword(ea + offset + 8)
                idc.MakeName(sName_dst, sName)
                if sName_type in need_create_function:
                    # flags = idc.GetFlags(ea)
                    print("Start fix Function %s at %s" % (sName, hex(sName_dst)))
                    idc.MakeCode(sName_dst)  # might not need
                    idc.MakeFunction(sName_dst, idc.BADADDR)
            ea += symbol_interval
        print("Fix function by symbol table finish.")
        print("Start IDA auto analysis, depending on the size of the firmware this might take a few minutes.")
        idaapi.autoWait()

    @staticmethod
    def fix_code(start_address, end_address):
        # Todo: There might be some data in the range of codes.
        offset = start_address
        while offset <= end_address:
            offset = idc.NextAddr(offset)
            flags = idc.GetFlags(offset)
            if not idc.isCode(flags):
                # Todo: Check should use MakeCode or MakeFunction
                # idc.MakeCode(offset)
                idc.MakeFunction(offset)

    @staticmethod
    def get_prev_ascii_string_address(address):
        """

        :param address: must be current ascii string start address.
        :return:
        """
        prev_string_start_address = address
        # string table interval should less than 5 bytes.
        if idc.Dword(address - 5) == 0:
            return None
        else:
            prev_string_start_address -= 5
            # TODO: Need handle short string.
            while idaapi.get_byte(prev_string_start_address) != 0:
                prev_string_start_address -= 1
            return prev_string_start_address + 1

    @staticmethod
    def get_next_ascii_string_address(address):
        """

        :param address: must be current ascii string start address.
        :return:
        """
        next_string_start_address = address
        # find current string end address
        while idaapi.get_byte(next_string_start_address) != 0:
            next_string_start_address += 1

        # string table interval should less than 5 bytes.
        # TODO: need handle short string.
        if idc.Dword(next_string_start_address + 1) == 0:
            return None

        while idaapi.get_byte(next_string_start_address) == 0:
            next_string_start_address += 1

        return next_string_start_address

    def get_string_table_start_address(self, address):
        string_table_start_address = address
        # find current string start address
        while idaapi.get_byte(string_table_start_address - 1) != 0:
            string_table_start_address -= 1

        while self.get_prev_ascii_string_address(string_table_start_address):
            string_table_start_address = self.get_prev_ascii_string_address(string_table_start_address)

        return string_table_start_address

    def fix_ascii(self, address):
        string_table_start_address = self.get_string_table_start_address(address)
        string_address = string_table_start_address
        while True:
            if string_address:
                print("Start Make string at address: %s" % hex(string_address))
                if idaapi.IDA_SDK_VERSION >= 700:
                    idc.create_strlit(string_address, idc.BADADDR)
                else:
                    idc.MakeStr(string_address, idc.BADADDR)
                string_address = self.get_next_ascii_string_address(string_address)
            else:
                break

    def run(self, arg):
        self.handler_auto_fix_idb()


try:
    class VxHunterMenuContext(idaapi.action_handler_t):

        @classmethod
        def get_name(self):
            return self.__name__

        @classmethod
        def get_label(self):
            return self.label

        @classmethod
        def register(self, plugin, label):
            self.plugin = plugin
            self.label = label
            instance = self()
            return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),  # Name. Acts as an ID. Must be unique.
                instance.get_label(),  # Label. That's what users see.
                instance  # Handler. Called when activated, and for updating
            ))

        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.get_name())

        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1

        @classmethod
        def update(self, ctx):
            try:
                if ctx.form_type == idaapi.BWN_DISASM:
                    return idaapi.AST_ENABLE_FOR_FORM
                else:
                    return idaapi.AST_DISABLE_FOR_FORM
            except:
                # Add exception for main menu on >= IDA 7.0
                return idaapi.AST_ENABLE_ALWAYS

    # context menu for Fix idb
    class VxHunterMCFixIDB(VxHunterMenuContext):
        def activate(self, ctx):
            self.plugin.handler_auto_fix_idb()
            return 1

    class VxHunterMCFixCode(VxHunterMenuContext):
        def activate(self, ctx):
            self.plugin.handler_fix_code()
            return 1

    class VxHunterMCFixAscii(VxHunterMenuContext):
        def activate(self, ctx):
            self.plugin.handler_fix_ascii()
            return 1

except Exception as err:
    # TODO: Add some handle later.
    pass


# register IDA plugin
def PLUGIN_ENTRY():
    return VxHunter_Plugin_t()



