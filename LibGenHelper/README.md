This module offsets simple interfaces to create import library.

How to use:

1. Create a ImportLibraryBuilder object, specified the dll's filename and the member name in library (often the same as dll's name, but others is also accepted).
2. Add import functions.
3. Call Builde method.
4. Get raw data from the object and save them into file.

Notice: `szFuncName` can be NULL (0), for that the function stub is not a must.

What is a function stub?

When calling a function from DLL, there are two ways declare the function,
take Sleep as example:

1. `extern "C" void __stdcall Sleep(unsigned int);`
2. `extern "C" __declspec(dllimport) void __stdcall Sleep(unsigned int);`

For 1, the linker will link it to `_Sleep@8` symbol, which is a function;
for 2, the linker will link it to `__imp__Sleep@8` symbol, which is a function pointer.

In x86 architecture, the first one will generate the code:

```
call _Sleep@8
```

and the second one will generate the code:

```
call dword ptr [__imp__Sleep@8]
```

Then what happened? the first one will jump to a function like this:

```
jmp dword ptr [__imp__Sleep@8]
```

So they work as the same. But for 1, `_Sleep@8` must exist.
