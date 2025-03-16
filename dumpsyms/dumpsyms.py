"""
DUMPSYMBOLS source code
Copyright (c) 2006-2025, Vladimir Kamenar.
All rights reserved.

This tool is a command-line utility to extract the dynamic-link library
symbols in JSON format. DUMPSYMBOLS supports both 32 and 64-bit DLLs.

The DUMPSYMBOLS tool expects a DLL name and an output file name, for example:
DUMPSYMBOLS \windows\system32\kernel32.dll kernel32.json

The output file name is optional. If not specified, a .json file with the
same name as the DLL will be generated.

Optional switches:
/COMPACT - don't include comments with misc information

The output JSON structure includes:
- dllname: The name of the DLL.
- arch: Architecture (32 or 64-bit).
- symbols: A list of symbols, each containing:
  - cconv: Calling convention (STDCALL).
  - name: Symbol name or ordinal value.
  - ord: Ordinal name.
  - thunk: Thunk name.
  - pubname: Public name.

Example JSON output:
{
  "dllname": "kernel32.dll",
  "arch": 64,
  "symbols": [
    {
      "cconv": "STDCALL",
      "name": "_ExitProcess@4",
      "ord": 1,
      "thunk": "_ExitProcess@4",
      "pubname": "__imp__ExitProcess@4"
    }
  ]
}
"""
import json
import struct
import os
import sys
from pathlib import Path

# Error codes and messages
ERR_CODES = {
    'ERR_OK': 0,
    'ERR_FILE_NOT_FOUND': 1,
    'ERR_OUTPUT': 2,
    'ERR_BAD_FORMAT': 3,
    'ERR_NO_EXPORT': 4,
    'ERR_NO_FREE_MEM': 5,
    'ERR_BAD_FILENAME': 6
}

error_msgs = [
    ": File locked or not found\n",
    ": Error opening the output file\n",
    ": Unreadable or invalid PE image\n",
    ": No export found\n",
    ": Not enough memory\n",
    ": Not a valid filename\n"
]

class RVA2FileOffset:
    def __init__(self, virtual_address, virtual_size, file_offset):
        self.virtual_address = virtual_address
        self.virtual_size = virtual_size
        self.file_offset = file_offset

def do_rva_to_file_offset(sections, rva):
    for section in sections:
        if section.virtual_address <= rva <= section.virtual_address + section.virtual_size:
            return rva - section.virtual_address + section.file_offset
    return 0

def parse_pe(filename, compact):
    try:
        with open(filename, 'rb') as hFile:
            buf = hFile.read(0x40)
            if len(buf) != 0x40:
                return ERR_CODES['ERR_BAD_FORMAT']

            # Jump to the COFF File Header
            aux = struct.unpack_from('<I', buf, 0x3C)[0]
            hFile.seek(aux, os.SEEK_SET)
            file_pos = aux + 0x1A;
            buf = hFile.read(0x1A)
            if len(buf) != 0x1A or struct.unpack_from('<I', buf)[0] != 0x4550:
                return ERR_CODES['ERR_BAD_FORMAT']

            x64 = struct.unpack_from('<H', buf, 4)[0] == 0x8664
            num_sections = struct.unpack_from('<H', buf, 6)[0]

            # Check if optional header contains a reference to an export directory
            size_of_optional_header = struct.unpack_from('<H', buf, 0x14)[0]
            is_pe32plus = 0
            if size_of_optional_header > 2:
                aux = struct.unpack_from('<H', buf, 0x18)[0]
                if aux not in (0x10B, 0x20B):
                    return ERR_CODES['ERR_BAD_FORMAT']
                if aux == 0x20B:
                    is_pe32plus = 1

            # Initialize JSON structure
            json_output = {
                "dllname": Path(filename).name,
                "arch": 64 if x64 else 32,
                "symbols": []
            }

            aux = 0x78 if is_pe32plus else 0x68
            if size_of_optional_header < aux:
                return ERR_CODES['ERR_NO_EXPORT']

            # Jump to the Optional Header -> Data Directories -> Export Table
            aux -= 0xA
            file_pos += aux;
            hFile.seek(aux, os.SEEK_CUR)
            file_pos = file_pos - aux + size_of_optional_header - 2;
            buf = hFile.read(8)
            if len(buf) != 8:
                return ERR_CODES['ERR_BAD_FORMAT']

            export_dir = RVA2FileOffset(*struct.unpack_from('<II', buf), 0)
            if not export_dir.virtual_address or not export_dir.virtual_size:
                return ERR_CODES['ERR_NO_EXPORT']

            # Jump to the Section Headers Table
            hFile.seek(file_pos, os.SEEK_SET)

            sections = []
            for _ in range(num_sections):
                buf = hFile.read(0x28)
                if len(buf) != 0x28:
                    return ERR_CODES['ERR_BAD_FORMAT']
                section = RVA2FileOffset(
                    struct.unpack_from('<I', buf, 0x0C)[0],
                    struct.unpack_from('<I', buf, 0x08)[0],
                    struct.unpack_from('<I', buf, 0x14)[0]
                )
                sections.append(section)

            # Jump to the Export directory
            export_dir.file_offset = do_rva_to_file_offset(sections, export_dir.virtual_address)
            if not export_dir.file_offset:
                return ERR_CODES['ERR_BAD_FORMAT']
            hFile.seek(export_dir.file_offset, os.SEEK_SET)

            # Read in the Export directory Table
            export_dir_size = max(export_dir.virtual_size, 40)
            buf = hFile.read(export_dir_size)
            if len(buf) < export_dir_size:
                return ERR_CODES['ERR_BAD_FORMAT']

            ordinal_base = struct.unpack_from('<H', buf, 0x10)[0]
            num_pointers = struct.unpack_from('<I', buf, 0x14)[0]
            num_sections = struct.unpack_from('<I', buf, 0x18)[0]
            pointers_array = do_rva_to_file_offset(sections, struct.unpack_from('<I', buf, 0x1C)[0])
            psymbols_array = do_rva_to_file_offset(sections, struct.unpack_from('<I', buf, 0x20)[0])
            ordinals_array = do_rva_to_file_offset(sections, struct.unpack_from('<I', buf, 0x24)[0])

            if not num_pointers or not num_sections or not pointers_array or not psymbols_array or not ordinals_array:
                return ERR_CODES['ERR_NO_EXPORT']

            # Parse the Name Pointer RVA Table
            for _ in range(num_sections):
                # Get the symbol's name
                hFile.seek(psymbols_array, os.SEEK_SET)
                i = struct.unpack_from('<I', hFile.read(4))[0]
                psymbols_array += 4
                pub_name = ""
                if i:
                    file_pos = do_rva_to_file_offset(sections, i)
                    if not file_pos:
                        return ERR_CODES['ERR_BAD_FORMAT']
                    hFile.seek(file_pos, os.SEEK_SET)
                    pub_name = hFile.read(80).split(b'\x00', 1)[0].decode()

                # Get the symbol's ordinal
                hFile.seek(ordinals_array, os.SEEK_SET)
                ordinal = struct.unpack_from('<H', hFile.read(2))[0]
                ordinals_array += 2

                ord_val = ordinal + ordinal_base
                ord_name = f"ord.{ord_val}"

                if not pub_name:
                    pub_name = ord_name

                if not compact:
                    print(f"{Path(filename).stem}.{pub_name} ord.{ordinal + ordinal_base}")

                    # Get the symbol's RVA (just to check if it's a forwarder chain)
                    if ordinal & 0x80000000:
                        return ERR_CODES['ERR_BAD_FORMAT']
                    hFile.seek(pointers_array + ordinal * 4, os.SEEK_SET)
                    i = struct.unpack_from('<I', hFile.read(4))[0]
                    if export_dir.virtual_address <= i < export_dir.virtual_address + export_dir.virtual_size:
                        # It's a forwarder RVA
                        file_pos = do_rva_to_file_offset(sections, i)
                        if not file_pos:
                            return ERR_CODES['ERR_BAD_FORMAT']
                        hFile.seek(file_pos, os.SEEK_SET)
                        buf = hFile.read(512).split(b'\x00', 1)[0].decode()
                        print(f"  -> {buf}")


                symbol_data = {
                    "cconv": "STDCALL",
                    "name": pub_name,
                    "ord" : ord_val,
                    "thunk": pub_name,
                    "pubname": f"__imp_{pub_name}"
                }

                json_output["symbols"].append(symbol_data)

            return json_output

    except FileNotFoundError:
        return ERR_CODES['ERR_FILE_NOT_FOUND']
    except Exception as e:
        print(f"Unexpected error: {e}")
        return ERR_CODES['ERR_BAD_FORMAT']

def main():
    if len(sys.argv) < 2:
        print("USAGE: DUMPSYMBOLS file [output] [/COMPACT]")
        return 1

    filename = sys.argv[1]
    output_filename = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('/') else f"{filename}.txt"
    compact = '/COMPACT' in sys.argv

    result = parse_pe(filename, compact)
    if isinstance(result, int):
        print(f"Error: {error_msgs[result - 1]}")
        return result

    with open(output_filename, 'w') as hOut:
        json.dump(result, hOut, indent=2)

    return 0

if __name__ == "__main__":
    main()

