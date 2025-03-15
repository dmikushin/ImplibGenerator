#ifndef LIBGENHELPERFACTORY_H
#define LIBGENHELPERFACTORY_H

#include "LibGenHelperInterfaces.h"

namespace Sora
{
    extern "C" IImportLibraryBuilder* CreateX86ImpLibBuilder(LPCSTR szDllName, LPCSTR szMemberName);
    extern "C" IImportLibraryBuilder* CreateX64ImpLibBuilder(LPCSTR szDllName, LPCSTR szMemberName);
};

#endif
