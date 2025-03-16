/**
 * This program generates an import library from a JSON configuration file.
 * 
 * Usage:
 *   MakeImpLib <input json> <output lib>
 * 
 * The input JSON structure includes:
 * - dllname: The name of the DLL.
 * - arch: Architecture (32 or 64-bit).
 * - symbols: A list of symbols, each containing:
 *   - cconv: Calling convention (e.g., STDCALL).
 *   - name: Symbol name or ordinal value.
 *   - ord: Ordinal name.
 *   - thunk: Thunk name.
 *   - pubname: Public name.
 * 
 * Example JSON input:
 * {
 *   "dllname": "kernel32.dll",
 *   "arch": 64,
 *   "symbols": [
 *     {
 *       "cconv": "STDCALL",
 *       "name": "_ExitProcess@4",
 *       "ord": 1,
 *       "thunk": "_ExitProcess@4",
 *       "pubname": "__imp__ExitProcess@4"
 *     }
 *   ]
 * }
 */

#include <cstdlib>
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>
#include <vector>
#include <Windows.h>

#include "LibGenHelperFactory.h"
#include "LibGenHelperInterfaces.h"

using json = nlohmann::json;

struct MyMsgException {
  std::string fmt;
  std::string msg;
  MyMsgException(const char* p) : msg(p), fmt("%s") {}
  MyMsgException(const char* p1, const char* p2) : fmt(p1), msg(p2) {}
};

int main(int argc, char* argv[]) {
  try {
    if (argc == 3) {
      std::ifstream inputFile(argv[1]);
      if (!inputFile.is_open()) {
        throw MyMsgException("Fail to open input file!");
      }

      json j;
      inputFile >> j;

      std::string dllName = j["dllname"];
      int arch = j["arch"];
      auto symbols = j["symbols"];

      Sora::IImportLibraryBuilder* impBuilder;
      if (arch == 64) {
        impBuilder = Sora::CreateX64ImpLibBuilder(dllName.c_str(), dllName.c_str());
      } else {
        impBuilder = Sora::CreateX86ImpLibBuilder(dllName.c_str(), dllName.c_str());
      }

      for (const auto& symbol : symbols) {
        std::string cconv = symbol["cconv"];
        std::string name = symbol["name"];
        int ord = symbol["ord"];
        std::string thunk = symbol["thunk"];
        std::string pubname = symbol["pubname"];

        if (!name.empty()) {
          impBuilder->AddImportFunctionByName(pubname.c_str(), thunk.c_str(), name.c_str());
        } else {
          impBuilder->AddImportFunctionByOrdinal(pubname.c_str(), thunk.c_str(), ord);
        }
      }

      // Save file
      impBuilder->Build();

      int nFileSize = impBuilder->GetDataLength();
      std::vector<char> buffer(nFileSize);
      impBuilder->GetRawData(reinterpret_cast<PBYTE>(buffer.data()));

      std::ofstream outputFile(argv[2], std::ios::binary);
      if (!outputFile.is_open()) {
        throw MyMsgException("Fail to create library File!");
      }

      outputFile.write(buffer.data(), nFileSize);
      if (!outputFile) {
        throw MyMsgException("Failed to write to output file!");
      }

      impBuilder->Dispose();
    } else {
      std::cout << "Make import library from JSON\n"
                << "using: MakeImpLib <input json> <output lib>\n";
    }
  } catch (MyMsgException& e) {
    std::cerr << e.fmt << e.msg << std::endl;
    exit(EXIT_FAILURE);
  }
}
