# Ghidra-Win32 Plugin

The Ghidra-Win32 plugin aims to provide support for Win32 API reversing in PE executables.

### Usage

Right click on a Function in the *Decompile Window*, if the function is part of the Win32 API, the option `Lookup Win32 Documentation` would be available.

![](data/images/usage01.png)

Clicking on the option brings up the documentation window. It displays the function signature and possible constants for each parameter. You can also reach the MSDN page for this function in your browser by clicking on `MSDN Link`. In the bottom left panel we can type and search for a specific Win32 function.

![](data/images/usage02.png)


### Todo

- Parameter Constant Substitution for Win32 functions.
- Crawler support for other MSDN pages.
- UI / UX refinement.
