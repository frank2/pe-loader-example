# Reflective PE Loading

This repository is a C-based example of reflective PE loading with the Windows API.
In other words, it's an example of loading executables like DLLs and EXEs without the
use of APIs like `CreateProcess` and `LoadLibrary`. It is paired with a blogpost,
whose content is currently TBA.

## Building

Grab a copy of [CMake](https://cmake.org) for Windows and Microsoft Visual Studio.
With those installed, prepare the build environment for the example:

```
> cd pe-loader-example
> mkdir build
> cd build
> cmake ../
```

This will prepare the code to be built. Then, to build the examples, simply run the
following command:

```
> cmake --build ./
```

This will build the main loader executable as well as the two example binaries to
load. To test the loader's capabilities, the following command can be run to run
tests:

```
ctest -C Debug
```
