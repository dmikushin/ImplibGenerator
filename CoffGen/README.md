# COFF Object generator

This module is used for build Coff Object File.

How to build a COFF file using this module:

1. Get the proper factory to create other objects.
2. Create a CoffBuilder object
3. Create SectionBuilder object
4. Add the SectionBuilder object to CoffBuilder
5. Set section name and characteristic, add data to the section
6. Add necessary symbols to symbol table of CoffBuilder
7. Call PushRelocs to generate necessary symbols from relocation table
8. Call methods of CoffBuilder object from IHasRawData to get the COFF Object File's raw data
9. Save the data to file, then you get a COFF Object File.

Notice:

1. If you need aux symbols, create these symbols by CreateAuxSymbol method from SectionBuilder
2. Currently longname section is not supported
3. SymbolTable and StringTable are automatically created during creating the CoffBuilder object,
   RelocationTable is automatically created during creating the SectionBuilder object.
