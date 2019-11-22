meta:
  id: cisco_firmware
  endian: le
  title: Cisco Firmware Image layout
  application: Firmware Image
  file-extension: ros
seq:
  - id: image_header
    type: image_header
    size: 80
  - id: file_header
    type: file_header
    repeat: expr
    repeat-expr: image_header.file_count

types:
  image_header:
    seq:
      - id: unknown1
        size: 32
      - id: file_count
        type: u4
      - id: unknown2
        size: 28
      - id: version
        type: str
        size: 16
        encoding: UTF-8
  file_header:
    seq:
      - id: file_name
        type: str
        size: 16
        encoding: UTF-8
      - id: file_offset
        type: u4
      - id: file_length
        type: u4
      - id: file_type
        type: u4
      - id: unknown2
        type: u4

    instances:
      file_data:
        pos: file_offset
        size: file_length
        -webide-parse-mode: eager
    -webide-representation: "{value} (data_offs={file_offset})"


