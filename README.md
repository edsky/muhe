# muhe
Simulate loading and running programs.

### TODO

- [x] Implement gdtr entry
- [ ] Implement tls initialization
- [ ] Implement easy api hook
- [x] Implement dll reloc
- [ ] Implement the test framework
- [ ] Implement the debugger
- [ ] Implement weird dll redirection mechanism
- [ ] Implement wow64 syscall forwarding

### Installation

- run `.\vcpkg.exe install unicorn:x64-windows-static-md`

  > If an error is reported, Delete the following vcpkg code
  >
  > ```diff
  > ---
  >  ports/unicorn/portfile.cmake | 4 ----
  >  1 file changed, 4 deletions(-)
  > 
  > diff --git a/ports/unicorn/portfile.cmake b/ports/unicorn/portfile.cmake
  > index aee7b65b9..9f039937f 100644
  > --- a/ports/unicorn/portfile.cmake
  > +++ b/ports/unicorn/portfile.cmake
  > @@ -2,10 +2,6 @@ if(VCPKG_CMAKE_SYSTEM_NAME STREQUAL "WindowsStore")
  >      message(FATAL_ERROR "WindowsStore not supported")
  >  endif()
  >  
  > -if(VCPKG_CRT_LINKAGE STREQUAL "dynamic" AND VCPKG_LIBRARY_LINKAGE STREQUAL "static")
  > -    message(FATAL_ERROR "unicorn can currently only be built with /MT or /MTd (static CRT linkage)")
  > -endif()
  > -
  >  # Note: this is safe because unicorn is a C library and takes steps to avoid memory allocate/free across the DLL boundary.
  >  set(VCPKG_CRT_LINKAGE "static")
  >  
  > -- 
  > ```

- run `cargo build --release`