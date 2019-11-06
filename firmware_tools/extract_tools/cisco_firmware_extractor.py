# !/usr/bin/env python3
# coding=utf-8

import sys
import argparse
import os
import struct


parser = argparse.ArgumentParser(description='Cisco VxWorks firmware extractor')
parser.add_argument('-i',
                    '--input-firmware-path',
                    metavar='input_firmware_path',
                    help='Firmware path')

parser.add_argument('-o',
                    '--output-path',
                    metavar='output_path',
                    help='Extracted files store path')


def extract_firmware(source_file_data, output_path):
    """Cisco VxWorks firmware extract function

    :param source_file_data:
    :param output_path:
    :return:
    """
    file_count = struct.unpack("<I", source_file_data[0x20:0x24])[0]
    print("Found {} files in firmware".format(file_count))
    print("Star extract files")
    for i in range(file_count):
        file_name = source_file_data[0x50 + (i * 0x20):0x60 + (i * 0x20)]
        file_name = file_name.replace(b'\x00', b'')
        print("file_name: {}".format(file_name))
        file_offset = struct.unpack("<I", source_file_data[0x60 + (i * 0x20):0x60 + 4 + (i * 0x20)])[0]
        file_length = struct.unpack("<I", source_file_data[0x60 + 4 + (i * 0x20):0x60 + 8 + (i * 0x20)])[0]
        print("file_offset: {:#010x}".format(file_offset))
        print("file_length: {}".format(file_length))
        output_file = open("{}/{:#08x}_{}".format(output_path, file_offset, file_name.decode('utf-8'), ), 'wb')
        output_file.write(source_file_data[file_offset: file_offset + file_length])


if __name__ == '__main__':
    args = parser.parse_args()
    if len(sys.argv) == 1:  #
        parser.print_help()
        sys.exit(1)

    print("args.input_firmware_path: {}".format(args.input_firmware_path))
    if args.input_firmware_path:
        if os.path.isfile(args.input_firmware_path):
            try:
                firmware_file_data = open(args.input_firmware_path, "rb").read()

            except Exception as err:
                print("Can't read input file: {} because of {}".format(args.input_firmware_path, err))
                sys.exit(1)

        else:
            print("Can't read input file: {}".format(args.input_firmware_path))
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(1)

    print("args.output_path: {}".format(args.output_path))

    if args.output_path:
        if os.path.exists(args.output_path):
            if os.path.isdir(args.output_path):
                output_path = args.output_path
            else:
                print("output_path {} is not directory".format(args.output_path))
                sys.exit(1)

        else:
            try:
                os.makedirs(args.output_path, exist_ok=True)
                output_path = args.output_path
            except Exception as err:
                print("Can't create output folder : {} because of {}".format(args.output_path, err))
                sys.exit(1)

    else:
        input_file_name = os.path.basename(args.input_firmware_path)
        output_path = "./{}.extracted".format(input_file_name)
        temp_out_path = output_path
        index = 1
        while os.path.exists(output_path):
            output_path = "{}_{}".format(temp_out_path, index)
            index += 1

        try:
            os.makedirs(output_path)

        except Exception as err:
            print("Can't create output folder : {} because of {}".format(output_path, err))

    if firmware_file_data and output_path:
        extract_firmware(firmware_file_data, output_path)
