#include <cstdlib>
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>
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
      CHandle hFile(CreateFile(argv[2], GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, NULL));
      if ((HANDLE)hFile == INVALID_HANDLE_VALUE)
        throw MyMsgException("Fail to create library File!");

      if (SetFilePointer(hFile, nFileSize, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
        if (GetLastError() != 0)
          throw MyMsgException("Can't allocate disk space for output file!");

      if (SetEndOfFile(hFile) == FALSE)
        throw MyMsgException("Can't allocate disk space for output file!");

      CHandle hFileMap(CreateFileMapping(hFile, 0, PAGE_READWRITE, 0, nFileSize, 0));
      if ((HANDLE)hFileMap == NULL)
        throw MyMsgException("Can't map output file for writing!");

      LPVOID pFile = MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, 0);
      if (pFile == 0)
        throw MyMsgException("Can't map output file for writing!");

      impBuilder->GetRawData((PBYTE)pFile);
      impBuilder->Dispose();
      UnmapViewOfFile(pFile);
    } else {
      std::cout << "Make import library from JSON\n"
                << "using: MakeImpLib <input json> <output lib>\n";
    }
  } catch (MyMsgException& e) {
    std::cerr << e.fmt << e.msg << std::endl;
    exit(EXIT_FAILURE);
  }
}
