#ifndef LIBINTERFACES_H
#define LIBINTERFACES_H

#include "coffInterfaces.h"

namespace Sora {
class ILibraryBuilder : public IDispose, public IHasRawData {
public:
  // the name is limited to 14 bytes. No longname is supported.
  virtual void AddObject(LPCSTR szName, ICoffBuilder *) = 0;

  // call this method to calculate the offset for first and second link member
  // before retrive raw data
  virtual void FillOffsets() = 0;
};
}; // namespace Sora

#endif
