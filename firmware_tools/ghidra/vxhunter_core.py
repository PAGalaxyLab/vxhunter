# coding=utf-8
import logging
import re
import struct

default_check_count = 100

known_address = [0x80002000, 0x10000, 0x1000, 0xf2003fe4, 0x100000, 0x107fe0]

function_name_key_words = ['bzero', 'usrInit', 'bfill']

# VxWorks 5.5
vx_5_sym_types = [
    # 0x00,      # Undefined Symbol
    # 0x01,      # Global (external)
    # 0x02,      # Local Absolute
    0x03,  # Global Absolute
    0x04,  # Local .text
    0x05,  # Global .text
    0x06,  # Local Data
    0x07,  # Global Data
    0x08,  # Local BSS
    0x09,  # Global BSS
    0x12,  # Local Common symbol
    0x13,  # Global Common symbol
    0x40,  # Local Symbols related to a PowerPC SDA section
    0x41,  # Global Symbols related to a PowerPC SDA section
    0x80,  # Local symbols related to a PowerPC SDA2 section
    0x81,  # Local symbols related to a PowerPC SDA2 section
]

# VxWorks 6.8
vx_6_sym_types = [
    # 0x00,  # Undefined Symbol
    # 0x01,  # Global (external)
    # 0x02,  # Local Absolute
    0x03,  # Global Absolute
    0x04,  # Local .text
    0x05,  # Global .text
    0x08,  # Local Data
    0x09,  # Global Data
    0x10,  # Local BSS
    0x11,  # Global BSS
    0x20,  # Local Common symbol
    0x21,  # Global Common symbol
    0x40,  # Local Symbols
    0x41,  # Global Symbols
]

need_create_function = [0x04, 0x05]


class VxTarget(object):
    def __init__(self, firmware, vx_version=5, big_endian=False, logger=None):
        """
        :param firmware: data of firmware
        :param vx_version: 5 = VxWorks 5.x; 6= VxWorks 6.x
        :param big_endian: True = big endian; False = little endian
        :param logger: logger for the target (default: None)
        """
        self.big_endian = big_endian
        self._vx_version = vx_version
        self.symbol_table_start = None
        self.symbol_table_end = None
        self._string_table = []
        self._symbol_table = []
        self.symbols = []
        self.load_address = None
        self._firmware = firmware
        self._has_symbol = None
        if self._vx_version == 5:
            self._symbol_interval = 16
        elif self._vx_version == 6:
            self._symbol_interval = 20

        if logger is None:
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(logging.INFO)
            consolehandler = logging.StreamHandler()
            console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
            consolehandler.setFormatter(console_format)
            self.logger.addHandler(consolehandler)
        else:
            self.logger = logger
        self.prepare()

    def prepare(self):
        """ Trying to find symbol from image.

        :return: True if found symbol, False otherwise.
        """
        self.find_symbol_table()
        if self._has_symbol is False:
            return None
        self.logger.debug("has_symbol: {}".format(self._has_symbol))
        self.get_symbol_table()

    def _check_vxworks_endian(self):
        """ Get image endian from image file.

        :return:
        """
        data1 = self._firmware[self.symbol_table_start + 4:self.symbol_table_start + 4 + self._symbol_interval]
        data2 = self._firmware[self.symbol_table_start + 4 + self._symbol_interval:self.symbol_table_start + 4 + self._symbol_interval * 2]
        if data1[0:2] == data2[0:2]:
            self.logger.info("VxWorks endian: Big endian.")
            self.big_endian = True
        elif data1[2:4] == data2[2:4]:
            self.logger.info("VxWorks endian: Little endian.")
            self.big_endian = False
        else:
            self.logger.info("VxWorks endian unknown. Assuming little endian.")
            self.big_endian = False

    def _check_symbol_format(self, offset):
        """ Check offset is symbol table.

        :param offset: offset from image.
        :return: True if offset is symbol table, False otherwise.
        """
        check_data = self._firmware[offset:offset + self._symbol_interval * default_check_count]
        is_big_endian = True
        is_little_endian = True
        # check symbol data match struct
        for i in range(default_check_count):
            check_data_1 = check_data[i * self._symbol_interval:(i + 1) * self._symbol_interval]
            if len(check_data_1) < self._symbol_interval:
                self.logger.debug("check_data_1 length is too small: {}".format(len(check_data_1)))
                break

            if self._check_symbol_format_simple(check_data_1) is False:
                return False

        if self._vx_version == 5:
            self.logger.debug("Check VxWorks 5 symbol format")
            # check is big endian
            for i in range(9):
                check_data_1 = check_data[4 + i * self._symbol_interval:6 + i * self._symbol_interval]
                data2 = check_data[4 + (i + 1) * self._symbol_interval:6 + (i + 1) * self._symbol_interval]
                if check_data_1 != data2:
                    self.logger.debug("VxWorks binary is not big endian.")
                    is_big_endian = False
                    break

            # check is little endian
            for i in range(9):
                check_data_1 = check_data[6 + i * self._symbol_interval:8 + i * self._symbol_interval]
                data2 = check_data[6 + (i + 1) * self._symbol_interval:8 + (i + 1) * self._symbol_interval]
                if check_data_1 != data2:
                    self.logger.debug("VxWorks binary is not little endian.")
                    is_little_endian = False
                    break

            return is_big_endian ^ is_little_endian

        return True

    def _check_symbol_format_simple(self, data):
        """ Check single symbol format is correct.

        :param data: single symbol data.
        :return: True if data is symbol, False otherwise.
        """
        if self._vx_version == 5:
            # Check symbol type is valid
            sym_type = ord(data[14])
            if sym_type not in vx_5_sym_types:
                return False

            # symbol should end with '\x00'
            if data[15] != '\x00':
                return False

            # Check symbol group is '\x00\x00'
            if data[12:14] != '\x00\x00':
                return False

            # symbol_name point should not be zero
            if data[4:8] == '\x00\x00\x00\x00':
                return False

            # symbol value point should not be zero
            if data[8:12] == '\x00\x00\x00\x00':
                return False

            return True

        elif self._vx_version == 6:
            # Check symbol type is valid
            sym_type = ord(data[18])
            if sym_type not in vx_6_sym_types:
                return False

            # symbol should end with '\x00'
            if data[19] != '\x00':
                return False

            # Check symbol group is '\x00\x00'
            if data[16:18] != '\x00\x00':
                return False

            # symbol_name point should not be zero
            if data[4:8] == '\x00\x00\x00\x00':
                return False

            # TODO: Need handle this problem
            # sometime data[8:12] will be '\x00\x00\x00\x00'
            # if data[8:12] == '\x00\x00\x00\x00':
            #     return False
            return True

        return False

    def find_symbol_table(self):
        """ Find symbol table from image.

        :return:
        """
        for offset in range(len(self._firmware)):
            if self.symbol_table_start is None:
                if self._check_symbol_format(offset):
                    self.logger.info("symbol table start offset: {}".format((hex(offset))))
                    self.symbol_table_start = offset
                    self._has_symbol = True
                    break
            else:
                break

        if self.symbol_table_start:
            for i in range(self.symbol_table_start, len(self._firmware), self._symbol_interval):
                check_data = self._firmware[i:i + self._symbol_interval]

                if len(check_data) < self._symbol_interval:
                    self.logger.debug("check_data length is too small: {}".format(check_data))
                    break

                if self._check_symbol_format_simple(check_data):
                    self.symbol_table_end = i + self._symbol_interval
                    self.logger.debug("self.symbol_table_end: {:010x}".format(self.symbol_table_end))

                else:
                    self.logger.info("Symbol table end offset: {}".format(hex(self.symbol_table_end)))
                    break
        else:
            self.logger.error("Didn't find symbol table in this image")
            self._has_symbol = False

    def get_symbol_table(self):
        """ get symbol table data.

        :return: True if get symbol table data successful, False otherwise.
        """
        if self.symbol_table_start and self.symbol_table_end:
            self._check_vxworks_endian()

        else:
            return False

        for i in range(self.symbol_table_start, self.symbol_table_end, self._symbol_interval):
            symbol_name_addr = self._firmware[i + 4:i + 8]
            symbol_dest_addr = self._firmware[i + 8:i + 12]
            symbol_flag = ord(self._firmware[i + self._symbol_interval - 2])
            if self.big_endian:
                unpack_format = '>I'
            else:
                unpack_format = '<I'
            symbol_name_addr = int(struct.unpack(unpack_format, symbol_name_addr)[0])
            symbol_dest_addr = int(struct.unpack(unpack_format, symbol_dest_addr)[0])
            self.logger.debug("symbol_name_addr: {}; symbol_dest_addr: {}".format(symbol_name_addr, symbol_dest_addr))
            self._symbol_table.append({'symbol_name_addr': symbol_name_addr, 'symbol_name_length': None, 'symbol_dest_addr': symbol_dest_addr, 'symbol_flag': symbol_flag, 'offset': i})
        # self.logger.debug("self._symbol_table: %s" % self._symbol_table)
        self.logger.debug("len(self._symbol_table): {}".format(len(self._symbol_table)))
        self._symbol_table = sorted(self._symbol_table, key=lambda x: x['symbol_name_addr'])
        for i in range(len(self._symbol_table) - 1):
            self._symbol_table[i]['symbol_name_length'] = self._symbol_table[i + 1]['symbol_name_addr'] - \
                                                          self._symbol_table[i]['symbol_name_addr']
        self.logger.debug("len(self._symbol_table): {}".format(len(self._symbol_table)))
        return True

    @staticmethod
    def _is_printable(c):
        """
        Check Char is printable.

        :param c: char to check.
        :return: True if char is printable, False otherwise.
        """
        try:
            # Not python 3 compatible
            c.decode('ascii')
            return True
        except UnicodeDecodeError:
            return False

    def _is_func_name(self, string):
        """ Check target string is match function name format.

        :param string: string to check.
        :return: True if string is match function name format, False otherwise.
        """
        # function name length should less than 512 byte

        # If any of the data matches a predefined regex of bad characters, or if any character in the string is unprintable, or if its length is over
        # 512, we must return False.

        return len(string) <= 512 and not re.search(r'.*[\\%\+,&\/\)\(\[\]].*', string) and self._is_printable(string)

    def _get_prev_string_data(self, offset):
        """ Get previous string from giving offset.

        :param offset: offset of image.
        :return: string data, string start offset, string end offset.
        """
        while offset > 0:
            if self._firmware[offset].encode('hex') != '00':
                start_address = offset
                end_address = offset + 1
                while offset > 0:
                    if self._firmware[offset - 1].encode('hex') == '00':
                        start_address = offset
                        break
                    offset -= 1
                data = self._firmware[start_address:end_address]
                self.logger.debug("data: {}; start_address: {}; end_address: {}".format(data, hex(start_address), hex(end_address)))
                return data, start_address, end_address
            else:
                offset -= 1
        self.logger.debug("Done looking for previous string data.")
        return None, None, None

    def _get_next_string_data(self, offset):
        """ Get next string from giving offset.

        :param offset: offset of image.
        :return: string data, string start offset, string end offset.
        """
        while offset < len(self._firmware):
            if self._firmware[offset] != '\x00':
                start_address = offset
                end_address = offset
                while offset <= len(self._firmware):
                    offset += 1
                    if self._firmware[offset] == '\x00':
                        end_address = offset
                        break
                data = self._firmware[start_address:end_address]
                return data, start_address, end_address
            else:
                offset += 1
        return None, None, None

    # TODO: This whole thing might be able to be replaced by just searching for structs
    def find_string_table_by_key_function_index(self, key_offset):
        """ Find string table by VxWorks key function name offset in VxWorks image.

        :param key_offset: key function name offset in VxWorks image.
        :return:
        """
        self.logger.debug("Attempting to find string table by key function index with offset {}".format(hex(key_offset)))
        temp_str_tab_data = []
        if len(self._symbol_table) > default_check_count:
            count = default_check_count
        else:
            count = len(self._symbol_table)
        start_offset = key_offset
        end_offset = key_offset
        self.logger.debug("Initializing with start_offset = end_offset = {}".format(hex(key_offset)))

        while start_offset > 0:
            if self._is_printable(self._firmware[start_offset]) is True:
                # get string from offset
                string, start_address, end_address = self._get_prev_string_data(start_offset)
                self.logger.debug("string: {}; start_address: {}; end_address: {}".format(string, hex(start_address), hex(end_address)))
                # check string is function name
                if self._is_func_name(string) is False:
                    if len(temp_str_tab_data) < count:
                        self.logger.error("Can't find any string table with key index: {}".format(string))
                        return None, None
                    else:
                        self.logger.info("Found string table start address at {}".format(hex(start_address)))
                        break
                else:
                    temp_str_tab_data.append((string, start_address, end_address))

                # get previous string from offset
                prev_string, prev_start_address, prev_end_address = self._get_prev_string_data(start_address - 1)
                self.logger.debug("prev_string: {}, prev_start_address: {}, prev_end_address: {}".format(prev_string, hex(prev_start_address), hex(prev_end_address)))
                if prev_start_address:
                    # strings interval should less than 4
                    if 4 < (start_address - prev_end_address):
                        if len(temp_str_tab_data) < count:
                            self.logger.error("Can't find any string table with key index: {}".format(string))
                            return None, None
                        else:
                            self.logger.info("found string table start address at {}".format(hex(start_address)))
                            break
                    else:
                        start_offset = start_address - 1
                        self.logger.debug("start_offset: {}".format(start_offset))
                else:
                    break
            else:
                start_offset -= 1

        while end_offset < len(self._firmware):
            # find first printable char
            if self._is_printable(self._firmware[end_offset]) is True:
                # get string from offset
                string, start_address, end_address = self._get_next_string_data(end_offset)
                # check string is function name
                if self._is_func_name(string) is False:
                    if len(temp_str_tab_data) < count:
                        temp_str_tab_data = []
                        end_offset = end_address
                        continue
                    else:
                        self.logger.info("found string table end at {}".format(hex(end_address)))
                        break
                        # TODO: Dead code?
                        # start_offset = temp_str_tab_data[0][1]
                        # end_offset = temp_str_tab_data[-1][2]
                else:
                    temp_str_tab_data.append((string, start_address, end_address))

                # get next string from offset
                next_string, next_start_address, next_end_address = self._get_next_string_data(end_address)
                if next_start_address:
                    # strings interval should less than 4
                    if 4 < (next_start_address - end_address):
                        if len(temp_str_tab_data) < count:
                            self.logger.error("Can't find any string table with key index.")
                            return None, None
                        else:
                            self.logger.info("Found string table end at {}".format(hex(end_address)))
                            break
                    else:
                        end_offset = end_address
            else:
                end_offset += 1

        temp_str_tab_data = sorted(temp_str_tab_data, key=lambda x: (x[1]))
        table_start_offset = temp_str_tab_data[0][1]
        table_end_offset = temp_str_tab_data[-1][2]
        self.logger.info("Found a string table at: {} to {}".format(hex(table_start_offset), hex(table_end_offset)))
        return table_start_offset, table_end_offset

    def get_string_table(self, str_start_address, str_end_address):
        """ Get string table data from VxWorks image with string table start and end offset.

        :param str_start_address: string table start address.
        :param str_end_address: string table end address.
        :return:
        """
        self._string_table = []
        offset = str_start_address
        address = offset
        str_tab_data = []
        while offset <= str_end_address:
            if self._firmware[offset].encode('hex') == '00':
                while offset <= str_end_address:
                    offset += 1
                    if self._firmware[offset].encode('hex') != '00':
                        next_address = offset
                        string = self._firmware[address:next_address]
                        length = next_address - address
                        str_tab_data.append({'address': address, 'string': string, 'length': length})
                        offset = next_address
                        address = next_address
                        break
            else:
                offset += 1
        self._string_table = str_tab_data

    def _check_fix(self, func_index, str_index):
        """

        :param func_index:
        :param str_index:
        :return:
        """
        try:
            fault_count = 0
            self.logger.debug("Symbol table's first element: {}".format(self._symbol_table[0]))
            if len(self._symbol_table) <= default_check_count:
                count = len(self._symbol_table)
                self.logger.debug("Length of symbol table, {}, is less than default. Setting iteration count to actual length of table, {}.".format(len(self._symbol_table), count))
            else:
                count = default_check_count
                self.logger.debug("Length of symbol table, {}, is greater than default. Setting iteration count to default, {}.".format(len(self._symbol_table), count))
            for i in range(count):

                if (func_index >= len(self._symbol_table)) or (str_index >= len(self._string_table)):
                    self.logger.debug("_check_fix False: func_index greater than length of _symbol_table, or str_index greater than length of _string_table.")
                    return False
                self.logger.debug("str_index: {}; _string_table[str_index]: {}".format(str_index, self._string_table[str_index]))
                self.logger.debug("func_index: {}; _symbol_table[func_index]: {}".format(func_index, self._symbol_table[func_index]))
                if i == count - 1:
                    if fault_count < 10:
                        self.logger.debug("_check_fix True")
                        return True
                    else:
                        self.logger.debug("_check_fix False: Too many faults.")
                        return False

                if self._string_table[str_index]['length'] == self._symbol_table[func_index]['symbol_name_length']:
                    func_index += 1
                    str_index += 1
                    self.logger.debug("_check_fix continue")

                elif self._symbol_table[func_index]['symbol_name_length'] < self._string_table[str_index]['length']:
                    # Sometime Symbol name might point to mid of string.
                    fault_count += 1
                    func_index += 1
                else:
                    self.logger.debug("_check_fix False: symbol_name_length from func_index larger than length from str_index.")
                    return False
        except Exception as e:
            self.logger.exception(e)
            raise

    def find_loading_address(self):
        """ Find VxWorks image load address by automatic analysis.

        :return: Load address if found, None otherwise.
        """
        if self._has_symbol is False:
            return None

        for key_word in function_name_key_words:
            prefix_keyword = '\x00_' + key_word + '\x00'
            key_word = '\x00' + key_word + '\x00'
            if key_word in self._firmware is False and prefix_keyword in self._firmware is False:
                self.logger.info("Firmware does not contain a function named {}".format(key_word))
                return None
        try:
            key_function_index = self._firmware.index('\x00' + function_name_key_words[0] + '\x00')
            self.logger.debug("key_function_index: {}".format(key_function_index))
        except Exception as err:
            # Handler _ prefix symbols
            self.logger.exception("Exception occurred while loading key_function_index: {}. Continuing...".format(err))
            key_function_index = self._firmware.index('\x00_' + function_name_key_words[0] + '\x00')
            self.logger.debug("key_function_index: {}".format(key_function_index))

        str_start_address, str_end_address = self.find_string_table_by_key_function_index(key_function_index)
        self.get_string_table(str_start_address, str_end_address)
        import json
        with open('/Users/mydriasis/Desktop/symbol_table.log', 'w') as file_handle:
            file_handle.write(json.dumps(self._symbol_table))
        with open('/Users/mydriasis/Desktop/string_table.log', 'w') as file_handle:
            file_handle.write(json.dumps(self._string_table))

        # TODO: Need improve performance
        self.logger.info("Starting loading address analysis")
        for str_index in range(len(self._string_table)):
            for func_index in range(len(self._symbol_table)):
                self.logger.debug("self._string_table[str_index]['length']: {}".format(self._string_table[str_index]['length']))
                self.logger.debug("self._symbol_table[func_index]['symbol_name_length']: {}".format(self._symbol_table[func_index]['symbol_name_length']))
                if self._string_table[str_index]['length'] == self._symbol_table[func_index]['symbol_name_length']:
                    if self._check_fix(func_index, str_index) is True:
                        self.logger.debug("self._symbol_table[func_index]['symbol_name_addr']: {}".format(self._symbol_table[func_index]['symbol_name_addr']))
                        self.logger.debug("self._string_table[str_index]['address']: %s" % self._string_table[str_index]['address'])
                        self.load_address = self._symbol_table[func_index]['symbol_name_addr'] - \
                                            self._string_table[str_index]['address']
                        self.logger.info('load address is {}'.format(hex(self.load_address)))
                        return self.load_address
                else:
                    continue
        self.logger.error("We didn't find load address in this firmware, sorry!")

    def _check_load_address(self, address):
        """

        :param address:
        :return:
        """
        if not self._has_symbol:
            return False
        if len(self._symbol_table) > default_check_count:
            self.logger.debug("Length of symbol table greater than default. Setting iteration count to default of {}.".format(default_check_count))
            count = default_check_count
        else:
            count = len(self._symbol_table)
        self.logger.debug("symbol_table length is {}".format(count))
        for i in range(count):
            offset = self._symbol_table[i]['symbol_name_addr'] - address
            if offset <= 0:
                return False
            # TODO: Need improve, currently use string point to check.
            string, str_start_address, str_end_address = self._get_next_string_data(offset)
            if str_start_address != offset:
                self.logger.info("String {} at offset {} didn't match symbol table.".format(string, offset))
                return False
        self.logger.info('Load address is {}'.format(hex(address)))
        return True

    def quick_test(self):
        """ Using known load address list to match VxWorks image.

        :return: Load address if match known address, None otherwise.
        """
        if self._has_symbol is False:
            return None
        self.logger.debug("has_symbol: {}".format(self._has_symbol))
        for address in known_address:
            if self._check_load_address(address):
                self.load_address = address
                return self.load_address
            else:
                self.logger.info('Load address is not {}'.format(hex(address)))

    def cleanup(self):
        """ Clean up variables.

        :return:
        """
        self.big_endian = False
        self.symbol_table_start = None
        self.symbol_table_end = None
        self._string_table = []
        self._symbol_table = []
        self.load_address = None
        self._has_symbol = None

    def get_string_from_firmware_by_offset(self, string_offset):
        symbol_name = ""
        while True:
            if self._firmware[string_offset] != '\x00':
                symbol_name += self._firmware[string_offset]
                string_offset += 1

            else:
                break

        return symbol_name

    def get_symbols(self):
        self.symbols = []
        if self.load_address:
            for symbol in self._symbol_table:
                symbol_name_addr = symbol["symbol_name_addr"]
                symbol_dest_addr = symbol["symbol_dest_addr"]
                symbol_flag = symbol["symbol_flag"]
                symbol_name_firmware_addr = symbol_name_addr - self.load_address
                symbol_name = self.get_string_from_firmware_by_offset(symbol_name_firmware_addr)
                self.symbols.append({"symbol_name": symbol_name, "symbol_name_addr": symbol_name_addr, "symbol_dest_addr": symbol_dest_addr, "symbol_flag": symbol_flag})
            return self.symbols

        else:
            return None
