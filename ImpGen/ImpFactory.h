#ifndef IMPFACTORY_H
#define IMPFACTORY_H

#include "ImpInterfaces.h"

namespace Sora {
    extern "C" {
        IImpSectionBuilder* GetX86ImpSectionBuilder();
        IImpSectionBuilder* GetX64ImpSectionBuilder();
    }
};

#endif
