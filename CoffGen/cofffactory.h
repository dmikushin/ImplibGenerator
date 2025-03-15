#ifndef COFFFACTORIES_H
#define COFFFACTORIES_H

#include "coffInterfaces.h"

namespace Sora {
    extern "C" {
        ICoffFactory* GetX86CoffFactory();
        ICoffFactory* GetX64CoffFactory();
        ICoffFactory* GetIA64CoffFactory();
    }
};

#endif
