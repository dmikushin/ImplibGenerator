# Build sections for import data from DLL

This module is used for building sections for import data from DLL.

How to use:

1. Create CoffBuilder object by using the CoffGen module
2. Call methods of ImpSectionBuilder to add section(s) to CoffBuilder
3. Call PushRelocs of CoffBuilder object
4. Get data from CoffBuilder object

I think the method name is self-explaining.


## Recommend Usage

Put ImportDescriptor, ImportThunk, NullDescriptor, NullThunk in different coff object files,
or I don't know if it works.
