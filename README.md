# r2go116

## Description:
Quick & dirty r2 script to find function names and addresses and rename them in go <= 1.16 stripped binaries.
Other scripts that I found would not work since they were for go <= 1.12 and lots of things changed in the compiler/linker.

By no means this is perfect and reliable, it worked for me and hopefully it will work for others too.

## Usage:
```
r2 <yourgobin>
#!pipe /path/to/r2go116.py
```

During the analysis you may see r2 error messages such as
```
  af: Cannot find function at 0x00nnnnn
```
this is because I don't know :D Jumping to those addresses after analysis seems to show legitimate functions, with readable names, so I decided I wouldn't bother investigating.

Enjoy
