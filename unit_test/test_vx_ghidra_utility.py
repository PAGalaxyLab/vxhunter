from common import BaseTestCase, mock
import string

function_name_chaset = string.letters
function_name_chaset += string.digits
function_name_chaset += "_:.<>,*"  # For C++
function_name_chaset += "()~+-=/%"  # For C++ special eg operator+(ZafBignumData const &,long)


ghidra_builtin_types = [
    'undefined',
    'byte',
    'uint',
    'ushort',
    'bool',
    'complex16',
    'complex32',
    'complex8',
    'doublecomplex',
    'dwfenc',
    'dword',
    'filetime',
    'float10',
    'float16',
    'float2',
    'float4',
    'float8',
    'floatcomplex',
    'guid',
    'imagebaseoffset32',
    'imagebaseoffset64',
    'int16',
    'int3',
    'int5',
    'int6',
    'int7',
    'long',
    'longdouble',
    'longdoublecomplex',
    'longlong',
    'mactime',
    'prel31',
    'qword',
    'sbyte',
    'schar',
    'sdword',
    'segmentedcodeaddress',
    'shiftedaddress',
    'sqword',
    'sword',
    'wchar16',
    'wchar32',
    'uchar',
    'uint16',
    'uint3',
    'uint5',
    'uint6',
    'uint7',
    'ulong',
    'ulonglong',
    'undefined1',
    'undefined2',
    'undefined3',
    'undefined4',
    'undefined5',
    'undefined6',
    'undefined7',
    'undefined8',
    'wchar_t',
    'word'
]


def check_is_func_name(function_name):
    """ Check target string is match function name format.

    :param function_name: string to check.
    :return: True if string is match function name format, False otherwise.
    """
    # function name length should less than 512 byte
    if len(function_name) > 512:
        return False

    for c in function_name:
        if (c in function_name_chaset) is False:
            return False

    if function_name.lower() in ghidra_builtin_types:
        return False

    return True


def demangle_function(demangle_string):
    function_name = None
    function_return = None
    function_parameters = None
    function_name_end = len(demangle_string)

    # get parameters
    index = len(demangle_string) - 1
    if demangle_string[-1] == ')':
        # have parameters
        parentheses_count = 0
        while index >= 0:
            if demangle_string[index] == ')':
                parentheses_count += 1

            elif demangle_string[index] == '(':
                parentheses_count -= 1

            index -= 1

            if parentheses_count == 0:
                break

        function_name_end = index

    # get function name
    while index >= 0:
        if demangle_string[index] == ' ':
            temp_data = demangle_string[index + 1:function_name_end + 1]
            if temp_data == "*":
                function_name_end = index
                index -= 1

            elif check_is_func_name(temp_data):
                function_name = temp_data
                break

            else:
                function_name_end = index
                index -= 1

        elif index == 0:
            if demangle_string[function_name_end] == " ":
                temp_data = demangle_string[index:function_name_end]
            else:
                temp_data = demangle_string[index:function_name_end + 1]
            if check_is_func_name(temp_data):
                function_name = temp_data
            break

        else:
            index -= 1

    function_name_start = index
    function_parameters = demangle_string[function_name_end + 1:]

    if index != 0:
        # get function return
        function_return = demangle_string[:function_name_start]

    return function_return, function_name, function_parameters


class VxHunterGhidraUtilityTests(BaseTestCase):
    def setUp(self):
        super(VxHunterGhidraUtilityTests, self).setUp()

    def test_demangle_function_01(self):
        demangle_sting = "ios::operator *(void)"
        function_return, function_name, function_parameters = demangle_function(demangle_sting)
        self.assertEqual(None, function_return)
        self.assertEqual("ios::operator", function_name)
        self.assertEqual("*(void)", function_parameters)

    def test_demangle_function_02(self):
        demangle_sting = "undefined streambuf::underflow(void)"
        function_return, function_name, function_parameters = demangle_function(demangle_sting)
        self.assertEqual("undefined", function_return)
        self.assertEqual("streambuf::underflow", function_name)
        self.assertEqual("(void)", function_parameters)

    def test_demangle_function_03(self):
        demangle_sting = "undefined basic_string<char,string_char_traits<char>,__default_alloc_template<true,0>>::insert(unsigned int,unsigned int,char)"
        function_return, function_name, function_parameters = demangle_function(demangle_sting)
        self.assertEqual("undefined", function_return)
        self.assertEqual("basic_string<char,string_char_traits<char>,__default_alloc_template<true,0>>::insert", function_name)
        self.assertEqual("(unsigned int,unsigned int,char)", function_parameters)

    def test_demangle_function_04(self):
        demangle_sting = "operator [](unsigned int,void *)"
        function_return, function_name, function_parameters = demangle_function(demangle_sting)
        self.assertEqual(None, function_return)
        self.assertEqual("operator", function_name)
        self.assertEqual("[](unsigned int,void *)", function_parameters)

    def test_demangle_function_05(self):
        demangle_sting = "void * operator.new(unsigned int,void *)"
        function_return, function_name, function_parameters = demangle_function(demangle_sting)
        self.assertEqual("void *", function_return)
        self.assertEqual("operator.new", function_name)
        self.assertEqual("(unsigned int,void *)", function_parameters)

    def test_demangle_function_06(self):
        demangle_sting = "void operator.delete(void *,nothrow_t const &)"
        function_return, function_name, function_parameters = demangle_function(demangle_sting)
        self.assertEqual("void", function_return)
        self.assertEqual("operator.delete", function_name)
        self.assertEqual("(void *,nothrow_t const &)", function_parameters)

    def test_demangle_function_07(self):
        demangle_sting = "ZafBignumData::operator long(void)"
        function_return, function_name, function_parameters = demangle_function(demangle_sting)
        self.assertEqual(None, function_return)
        self.assertEqual("ZafBignumData::operator", function_name)
        self.assertEqual("long(void)", function_parameters)

    def test_demangle_function_08(self):
        demangle_sting = "long const * _ZafFindIf<long_const*,FindEventStruct>(long const *,long const *,FindEventStruct)"
        function_return, function_name, function_parameters = demangle_function(demangle_sting)
        self.assertEqual("long const *", function_return)
        self.assertEqual("_ZafFindIf<long_const*,FindEventStruct>", function_name)
        self.assertEqual("(long const *,long const *,FindEventStruct)", function_parameters)

    def test_demangle_function_09(self):
        demangle_sting = "ZafPullDownMenu::operator-(ZafWindowObject *)"
        function_return, function_name, function_parameters = demangle_function(demangle_sting)
        self.assertEqual(None, function_return)
        self.assertEqual("ZafPullDownMenu::operator-", function_name)
        self.assertEqual("(ZafWindowObject *)", function_parameters)

    def test_demangle_function_10(self):
        demangle_sting = "undefined ZafBignumData::operator*=(double)"
        function_return, function_name, function_parameters = demangle_function(demangle_sting)
        self.assertEqual("undefined", function_return)
        self.assertEqual("ZafBignumData::operator*=", function_name)
        self.assertEqual("(double)", function_parameters)

    def test_demangle_function_11(self):
        demangle_sting = "undefined CompareStruct<ZafObjectPersistence--CompareFunction>::operator()(ZafObjectPersistence::CompareFunction &)"
        function_return, function_name, function_parameters = demangle_function(demangle_sting)
        self.assertEqual("undefined", function_return)
        self.assertEqual("CompareStruct<ZafObjectPersistence--CompareFunction>::operator()", function_name)
        self.assertEqual("(ZafObjectPersistence::CompareFunction &)", function_parameters)

    def test_demangle_function_12(self):
        # TODO: Handler this case later
        demangle_sting = "undefined basic_string<char,string_char_traits<char>,__default_alloc_template<true,0>>::operator[](unsigned int)"
        function_return, function_name, function_parameters = demangle_function(demangle_sting)
        self.assertEqual("undefined", function_return)
        self.assertEqual("basic_string<char,string_char_traits<char>,__default_alloc_template<true,0>>::operator", function_name)
        self.assertEqual("[](unsigned int)", function_parameters)
