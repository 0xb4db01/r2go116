# r2go116

## Description:
Quick & dirty r2 script to find function names and addresses and rename them in go >= 1.16 stripped binaries.
Other scripts that I found would not work since they were for go <= 1.12 and lots of things changed in the compiler/linker.

By no means this is perfect and reliable, it worked for me and hopefully it will work for others too.

## Usage:
```
r2 <yourgobin>
#!pipe /path/to/r2go116.py
```

Example:
```
r2go116 % r2 hello.elf
 -- It's not you, it's me.
[0x0045c200]> afl
[0x0045c200]>
[0x0045c200]> #!pipe python3 ./r2go116.py
Analysing hello.elf
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Find function and symbol names from golang binaries (aang)
[x] Found no symbols.
[x] Analyze all flags starting with sym.go. (aF @@f:sym.go.*)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information (aanr)
[x] Use -AA or aaaa to perform additional experimental analysis.
0x0047e060    3 66           fmt_glob__func1
0x0047e0c0    9 197          fmt_init
0x0047e1a0    7 141          type__eq_fmt_fmt
0x0047e240    3 103          main_main
[0x0045c200]>
```

During the analysis you may see r2 error messages such as
```
  af: Cannot find function at 0x00nnnnn
```
this is because I don't know :D Jumping to those addresses after analysis seems to show legitimate functions, with readable names, so I decided I wouldn't bother investigating.

Enjoy
