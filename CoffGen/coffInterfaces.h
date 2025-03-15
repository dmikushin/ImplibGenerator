#ifndef COFFINTERFACES_H
#define COFFINTERFACES_H

#include <Windows.h>

namespace Sora {
    //indicate that the object offers method to free
    class IDispose
    {
        public:
            virtual void Dispose() = 0;
    };

    //indicate that the object can output binary datas
    class IHasRawData
    {
        public:
            virtual int GetDataLength() = 0;

            //the memory should be allocated by the caller
            virtual void GetRawData(PBYTE) = 0;
    };

    class ICoffBuilder; //for building coff object file
    class ISectionBuilder; //for building section of coff object file
    class IStringTableBuilder; //for building string table of coff object file
    class ISymbolStrings; //for enum each symbol string in symbol table
    class ISymbolTableBuilder; //for building symbol table of coff object file
    class ISectionAuxSymbol; //present a aux symbol in symbol table
    class IRelocatableVar; //present a relocation item in relocation table
    class IRelocationTableBuilder; //for building relocation table of coff object file

    class ICoffFactory
    {
        public:
            virtual ICoffBuilder* CreateCoffBuilder() = 0;
            virtual ISectionBuilder* CreateSectionBuilder() = 0;

            //generally this function is not called by user.
            virtual ISymbolTableBuilder* CreateSymbolTableBuilder() = 0;

            //generally this function is not called by user.
            virtual IStringTableBuilder* CreateStringTableBuilder() = 0;

            virtual IRelocatableVar* CreateRelocatableVar() = 0;

            //generally this function is not called by user.
            virtual IRelocationTableBuilder* CreateRelocationTableBuilder() = 0;
    };

    class ICoffBuilder : public IDispose, public IHasRawData
    {
        public:
            //return: index in secions, 1-based. this function will set the section index
            //the ownership of object is transferred
            virtual int AppendSection(ISectionBuilder*) = 0;

            virtual IStringTableBuilder* GetStringTableBuilder() = 0;
            virtual ISymbolTableBuilder* GetSymbolTableBuilder() = 0;

            //call turns: add symbol -> PushRelocs. the function will reference relocs to previous added symbols
            virtual void PushRelocs() = 0;
    };

    enum SectionCharacteristic
    {
        SECH_READ = 1,
        SECH_WRITE = 2,
        SECH_EXEC = 4,
        SECH_CODE = 8,
        SECH_ALIGN1 = 16,
        SECH_ALIGN2 = 32,
        SECH_ALIGN4 = 64,
        SECH_ALIGN8 = 128,
        SECH_ALIGN16 = 256,
        SECH_ALIGN32 = 512,
        SECH_ALIGN64 = 1024,
        SECH_UNINIT = 2048,
        SECH_COMDAT = 4096
    };

    enum SectionComdat
    {
        SECO_NODUPLICATE = 1,
        SECO_SELECTANY,
        SECO_SELECTSAMESIZE,
        SECO_SELECTSAME,
        SECO_ASSOCIATIVE,
        SECO_SELECTLARGEST
    };

    class ISectionBuilder : public IDispose
    {
        public:
            //ownership of relocationItems will transfer to this object
            //the offset in relocatableVar is relative to the beginning of pData
            virtual void AppendData(LPCBYTE pData, int len, IRelocatableVar*[], int relocCount) = 0;

            virtual void SetCharacteristics(DWORD) = 0;
            virtual void SetName(LPCSTR) = 0; //set section name, max length: 8 chars

            virtual int GetHeaderLength() = 0;

            //param 2: offset (base) of the section in the data part
            virtual void GetRawHeader(PBYTE, DWORD rawOffset) = 0;

            virtual int GetDataLength() = 0; //not include the header
            virtual void GetRawData(PBYTE) = 0; //not include the header either

            //please don't call setsectionindex by hand unless you know what you are doing.
            //it's called by the coff builder
            virtual void SetSectionIndex(int) = 0; 

            virtual int GetSectionIndex() = 0; //1-based

            //please don't call pushrelocs by hand unless you know what you are doing.
            //this will be called by coff builder's pushrelocs
            virtual void PushRelocs(ISymbolTableBuilder*) = 0;

            //input: SectionCharacteristic output: raw characteristic
            virtual DWORD GetRawCharacteristic(DWORD) = 0; //object independent

            //return the raw characteristic of this object
            virtual DWORD GetRawCharacteristic() = 0;

            //no crc is generated in aux symbol
            //associated section can be null
            virtual ISectionAuxSymbol* CreateAuxSymbol(ISectionBuilder* associatedSection, SectionComdat selection) = 0;
    };

    class IStringTableBuilder : public IDispose, public IHasRawData
    {
        public:
            //return the offset of appended string
            virtual int AppendString(LPCSTR) = 0;

            //don't free the returned value, it's inside the string table
            virtual LPCSTR GetString(int offset) = 0;
    };

    enum StorageType
    {
        SYST_EXTERN = 1,
        SYST_STATIC,
        SYST_SECTION,
        SYST_FUNCTION,
        SYST_STATICFUNCTION
    };

    class ISymbolStrings : public IDispose
    {
        public:
            virtual int GetCount() = 0;
            virtual LPCSTR GetString(int nIndex) = 0;
    };

    class ISymbolTableBuilder : public IDispose, public IHasRawData
    {
        public:
            //return the index of added item, 0-based
            //value: often the offset.
            //value could be size when add extern reference though often 0 here.
            virtual int AddSymbol(ISectionBuilder* section, int value, LPCSTR name, StorageType, int auxCnt) = 0;

            //data is copied. after the function returned the parameter can be freed
            //often ISectionAuxSymbol*
            //ownership is not transfered, don't forget to free it
            virtual int AddAuxData(IHasRawData*) = 0;

            virtual int GetSymbolCount() = 0;

            //please don't call setsectionindex by hand.
            virtual void SetStringTable(IStringTableBuilder*) = 0;

            //the caller has responsibility to free the returned object
            virtual ISymbolStrings* GetPublicSymbolNames() = 0;
    };

    enum RelocateType {
        VARelocate32 = 1,
        VARelocate64,
        RVARelocate
    };

    class IRelocatableVar : public IDispose
    {
        public:
            //change the inside offset value of this object by add the parameter value
            virtual void Offset(int offset) = 0;

            //section and offset point to the mem that should be rewrite during linking
            virtual void Set(LPCSTR symbol, ISectionBuilder* section, DWORD offset, int size, DWORD relocType) = 0;

            virtual void Get(LPCSTR* symbol, ISectionBuilder** section, DWORD* offset, int* size, DWORD* relocType) = 0;
    };

    class IRelocationTableBuilder : public IDispose, public IHasRawData
    {
        public:
            //get the bytes of a pointer. 4 for x86 and 8 for x64
            virtual int GetPtrLength() = 0;

            //it's used during build section header
            //generally you don't need call this method unless you know what you are doing
            virtual int GetCount() = 0;

            //ownership is transfered
            virtual void AppendRelocationItem(IRelocatableVar*) = 0;

            //this will be called by section builder's pushrelocs
            virtual void PushToSymbolTable(ISymbolTableBuilder*) = 0;
    };

    class ISectionAuxSymbol : public IHasRawData, public IDispose
    {
    };
};

#endif
