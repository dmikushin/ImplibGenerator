/*
 * DUMPSYMBOLS source code
 * Copyright (c) 2006-2025, Vladimir Kamenar.
 * All rights reserved.
 *
 * This tool is a command-line utility to extract the dynamic-link library
 * symbols in plain text format. DUMPSYMBOLS supports both 32 and 64-bit DLL.
 *
 * The DUMPSYMBOLS tool expects a DLL name and an output file name, for example:
 * DUMPSYMBOLS \windows\system32\kernel32.dll kernel32.txt
 *
 * The output file name is optional. If not specified, a .txt with the
 * same name as the DLL will be generated.
 *
 * Optional switches:
 * /COMPACT - don't include comments with misc information
 *
 * The output file uses the following format:
 * MACRO implib   dllname, cconv, name, thunk, pubname
 * Parameters:
 *     dllname  : DLL file name.
 *     cconv    : Calling convention. Possible values: STDCALL, CDECL
 *     name     : Symbol name or an ordinal value, prefixed with ord. This value should
 *                match exactly the required DLL exported symbol.
 *     thunk    : Optional thunk name. A thunk function consists of a single
 *                jmp [pubname] instruction. If not specified, 'name' is assumed
 *                to be the thunk name as well.
 *     pubname  : Optional public name. This symbolic name allows calling an external
 *                function directly (not using a thunk). If not specified, 'name'
 *                prefixed with '__imp_' is used as the pubname.
 * Examples:
 *     implib dsound.dll,   ord.1, _DirectSoundCreate@12
 *     implib kernel32.dll, ExitProcess, _ExitProcess@4, __imp__ExitProcess@4
 */

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

// Error codes
enum ERR_CODES {
  ERR_OK,
  ERR_FILE_NOT_FOUND,
  ERR_OUTPUT,
  ERR_BAD_FORMAT,
  ERR_NO_EXPORT,
  ERR_NO_FREE_MEM,
  ERR_BAD_FILENAME
};

// Error messages
const char *error_msgs[] = {"\": File locked or not found\n",
                            "\": Error opening the output file\n",
                            "\": Unreadable or invalid PE image\n",
                            "\": No export found\n",
                            "\": Not enough memory\n",
                            "\": Not a valid filename\n"};

// Syntax mods
#define MOD_NO 0

struct RVA_2_FileOffset {
  uint32_t VirtualAddress;
  uint32_t VirtualSize;
  uint32_t FileOffset;
};

struct RVA_2_FileOffset_node {
  RVA_2_FileOffset node;
  RVA_2_FileOffset_node *next_node;
};

// Convert an RVA value into a regular file offset
uint32_t do_RVA_2_FileOffset(RVA_2_FileOffset_node *sections, uint32_t RVA) {
  while (sections) {
    if (RVA >= sections->node.VirtualAddress &&
        RVA <= sections->node.VirtualAddress + sections->node.VirtualSize) {
      return RVA - sections->node.VirtualAddress + sections->node.FileOffset;
    }
    sections = sections->next_node;
  }
  return 0;
}

// Process a single PE file (DLL) and dump its export
int parse_pe(const std::string &filename, std::ifstream &hFile,
             std::ofstream &hOut, bool compact) {
  fs::path dll_path(filename);
  std::string dll_name = dll_path.stem().string();
  char buf[1024], pub_name[80];
  int current_mod = MOD_NO;
  char c;
  std::stringstream ss;
  RVA_2_FileOffset export_dir;
  RVA_2_FileOffset_node *sections = nullptr, **current_node = &sections;
  uint32_t dll_name_len, aux, i, file_pos, size_of_optional_header, is_PE32plus,
      num_sections;
  uint32_t ordinal_base, num_pointers, ordinals_array, pointers_array,
      psymbols_array, pub_name_len;
  uint16_t ordinal;

  // Open the file
  hFile.open(filename, std::ios::binary);
  if (!hFile.is_open())
    return ERR_FILE_NOT_FOUND;

  // Read in a fragment of the MSDOS header
  hFile.read(buf, 0x40);
  if (hFile.gcount() != 0x40)
    return ERR_BAD_FORMAT;

  // Jump to the COFF File Header
  aux = *reinterpret_cast<uint32_t *>(buf + 0x3C);
  hFile.seekg(aux, std::ios::beg);
  file_pos = aux + 0x1A;

  // Read in the COFF file header
  hFile.read(buf, 0x1A);
  if (hFile.gcount() != 0x1A || *reinterpret_cast<uint32_t *>(buf) != 0x4550)
    return ERR_BAD_FORMAT;
  bool x64 = *reinterpret_cast<uint16_t *>(buf + 4) == 0x8664;
  num_sections = *reinterpret_cast<uint8_t *>(buf + 6);

  // Check if optional header contains a reference to an export directory
  size_of_optional_header = *reinterpret_cast<uint16_t *>(buf + 0x14);
  is_PE32plus = 0;
  if (size_of_optional_header > 2) {
    aux = *reinterpret_cast<uint16_t *>(buf + 0x18);
    if (aux != 0x10B && aux != 0x20B)
      return ERR_BAD_FORMAT;
    if (aux == 0x20B)
      is_PE32plus = 1;
  }

  // DEF header
  hOut << "include 'implib" << (x64 ? "64" : "") << ".inc'\n\n";

  aux = is_PE32plus ? 0x78 : 0x68;
  if (size_of_optional_header < aux)
    return ERR_NO_EXPORT;

  // Jump to the Optional Header -> Data Directories -> Export Table
  aux -= 0xA;
  file_pos += aux;
  hFile.seekg(aux, std::ios::cur);
  file_pos = file_pos - aux + size_of_optional_header - 2;
  hFile.read(reinterpret_cast<char *>(&export_dir), 8);
  if (hFile.gcount() != 8)
    return ERR_BAD_FORMAT;
  if (!export_dir.VirtualAddress || !export_dir.VirtualSize)
    return ERR_NO_EXPORT;

  // Jump to the Section Headers Table
  hFile.seekg(file_pos, std::ios::beg);

  // Load all section bounds into a linked list
  while (num_sections--) {
    hFile.read(buf, 0x28);
    if (hFile.gcount() != 0x28)
      return ERR_BAD_FORMAT;
    *current_node = new RVA_2_FileOffset_node;
    if (!*current_node)
      return ERR_NO_FREE_MEM;
    (*current_node)->node.VirtualAddress =
        *reinterpret_cast<uint32_t *>(buf + 0x0C);
    (*current_node)->node.VirtualSize =
        *reinterpret_cast<uint32_t *>(buf + 0x08);
    (*current_node)->node.FileOffset =
        *reinterpret_cast<uint32_t *>(buf + 0x14);
    current_node = &(*current_node)->next_node;
  }

  // Jump to the Export directory
  export_dir.FileOffset =
      do_RVA_2_FileOffset(sections, export_dir.VirtualAddress);
  file_pos = export_dir.FileOffset;
  if (!file_pos)
    return ERR_BAD_FORMAT;
  hFile.seekg(file_pos, std::ios::beg);

  // Read in the Export directory Table
  aux = 40;
  if (export_dir.VirtualSize < 40) {
    aux = export_dir.VirtualSize;
    std::memset(buf, 0, 40);
  }
  hFile.read(buf, aux);
  ordinal_base = *reinterpret_cast<uint16_t *>(buf + 0x10);
  num_pointers = *reinterpret_cast<uint32_t *>(buf + 0x14);
  num_sections = *reinterpret_cast<uint32_t *>(buf + 0x18);
  pointers_array =
      do_RVA_2_FileOffset(sections, *reinterpret_cast<uint32_t *>(buf + 0x1C));
  psymbols_array =
      do_RVA_2_FileOffset(sections, *reinterpret_cast<uint32_t *>(buf + 0x20));
  ordinals_array =
      do_RVA_2_FileOffset(sections, *reinterpret_cast<uint32_t *>(buf + 0x24));
  if (!num_pointers || !num_sections || !pointers_array || !psymbols_array ||
      !ordinals_array)
    return ERR_NO_EXPORT;

  // Parse the Name Pointer RVA Table
  while (num_sections--) {
    // Get the symbol's name
    hFile.seekg(psymbols_array, std::ios::beg);
    hFile.read(reinterpret_cast<char *>(&i), 4);
    psymbols_array += 4;
    pub_name[0] = 0;
    if (i) {
      file_pos = do_RVA_2_FileOffset(sections, i);
      if (!file_pos)
        return ERR_BAD_FORMAT;
      hFile.seekg(file_pos, std::ios::beg);
      hFile.read(pub_name, sizeof(pub_name) - 3);
      pub_name[hFile.gcount()] = 0;
    }

    // Get the symbol's ordinal
    hFile.seekg(ordinals_array, std::ios::beg);
    hFile.read(reinterpret_cast<char *>(&ordinal), 2);
    ordinals_array += 2;
    pub_name_len = std::strlen(pub_name);
    if (!pub_name_len) {
      ss.str(""); // Clear the stringstream
      ss << "ord." << (ordinal + ordinal_base);
      std::strcpy(pub_name, ss.str().c_str());
      pub_name_len = ss.str().length();
    }
    if (!compact) {
      // ; DLLNAME.NAME ord.#
      ss.str(""); // Clear the stringstream
      ss << "; " << dll_name << '.' << pub_name << " ord." << (ordinal + ordinal_base) << '\n';
      hOut << ss.str();

      // Get the symbol's RVA (just to check if it's a forwarder chain)
      if (ordinal & 0x80000000)
        return ERR_BAD_FORMAT;
      hFile.seekg(pointers_array + ordinal * 4, std::ios::beg);
      hFile.read(reinterpret_cast<char *>(&i), 4);
      if (i >= export_dir.VirtualAddress &&
          i < export_dir.VirtualAddress + export_dir.VirtualSize) {
        // It's a forwarder RVA
        file_pos = do_RVA_2_FileOffset(sections, i);
        if (!file_pos)
          return ERR_BAD_FORMAT;
        hFile.seekg(file_pos, std::ios::beg);
        ss.str(""); // Clear the stringstream
        ss << "; -> ";
        hFile.read(buf, 512);
        buf[hFile.gcount()] = 0;
        ss << buf;
        if (ss.str().length() <= 5) {
          ss << "...";
        }
        ss << '\n';
        hOut << ss.str();
      }
    }

    hOut << "implib ";
    hOut << filename;
    if (current_mod != MOD_NO) {
      hOut << ", STDCALL, 0, ";
    } else {
      hOut << ", ";
    }
    pub_name[pub_name_len++] = '\n';
    hOut.write(pub_name, pub_name_len);
  }
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "USAGE: DUMPSYMBOLS file [output] [/COMPACT]\n";
    return 1;
  }

  std::string filename = argv[1];
  std::string output_filename =
      (argc > 2 && argv[2][0] != '/') ? argv[2] : filename + ".txt";
  bool compact = false;

  // Check for /COMPACT switch
  for (int i = 2; i < argc; ++i) {
    if (std::strcmp(argv[i], "/COMPACT") == 0) {
      compact = true;
    }
  }

  std::ifstream hFile;
  std::ofstream hOut(output_filename);

  if (!hOut.is_open()) {
    std::cerr << "Error opening the output file\n";
    return ERR_OUTPUT;
  }

  int result = parse_pe(filename, hFile, hOut, compact);
  if (result != ERR_OK) {
    std::cerr << "Error: " << error_msgs[result - 1] << "\n";
  }

  hOut << "\nendlib\n";
  return 0;
}
