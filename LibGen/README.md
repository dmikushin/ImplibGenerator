# Module for creating .lib file

This module is used for creating Object Archive (library, .lib) file.

How to use:

1. Create CoffBuilder object by using CoffGen module, and add section to it
2. Call PushRelocs of CoffBuilder object, like what you do before save this object file
3. Call AddObject method of LibraryBuilder object with member name. For import library, all member name is the same.
4. Call FillOffsets to calculate and fill all member's offset(file pointer) for first link member and second link member
5. Get raw data from LibraryBuilder object and save them into file.
