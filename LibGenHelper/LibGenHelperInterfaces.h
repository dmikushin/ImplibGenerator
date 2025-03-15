#ifndef LIBGENHELPERINTERFACES_H
#define LIBGENHELPERINTERFACES_H

#include "coffInterfaces.h"

namespace Sora {
class IImportLibraryBuilder : public IHasRawData, public IDispose {
public:
  // szImpName: __imp__Sleep@8
  // szFuncName: _Sleep@8, can be null, will not generate stub
  // szImportName: Sleep
  virtual void AddImportFunctionByName(LPCSTR szImpName, LPCSTR szFuncName,
                                       LPCSTR szImportName) = 0;
  virtual void AddImportFunctionByOrdinal(LPCSTR szImpName, LPCSTR szFuncName,
                                          int nOrdinal) = 0;

  // call after add all import items
  virtual void Build() = 0;

  // hint means ordinal
  virtual void AddImportFunctionByNameWithHint(LPCSTR szImpName,
                                               LPCSTR szFuncName,
                                               LPCSTR szImportName,
                                               int nOrdinal) = 0;
};
}; // namespace Sora

#endif
