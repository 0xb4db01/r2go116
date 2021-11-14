#!/usr/local/bin/python3

import struct
import json
import logging
import r2pipe

##
# r2go116 by 0xb4db01
#
# Description:
# Quick & dirty r2 script to find function names and addresses and rename them
# in go <= 1.16 stripped binaries.
# Other scripts that I found would not work since they were for go <= 1.12 and
# lots of things changed in the compiler/linker.
#
# By no means this is perfect and reliable, it worked for me and hopefully it
# will work for others too.
#
# Usage:
# r2 <yourgobin>
# #!pipe /path/to/r2go116.py
#
# During the analysis you may see r2 error messages such as
#   af: Cannot find function at 0x00nnnnn
# this is because I don't know :D Jumping to those addresses after analysis
# seems to show legitimate functions, with readable names, so I decided I
# wouldn't bother investigating.
#
# Enjoy
#

try:
    import coloring
except:
    coloring = None

r2 = r2pipe.open()

GO116MAGIC = b'\xfa\xff\xff\xff\x00\x00'

def rename_function(function_name: str):
    '''
    @brief go functions have all those weird characters, replace them with _
    @param function_name a string with the original function's name
    @return string for renamed function
    '''
    tmp = str(function_name).replace('(*', '__ptr_')
    tmp = tmp.replace(')', '__')
    tmp = tmp.replace('/', '_')
    tmp = tmp.replace('.', '_')
    tmp = tmp.replace('[', '_')
    tmp = tmp.replace(']', '_')

    return tmp

def get_functions_addresses(filename: str):
    '''
    @brief This is where things get funky as hell..
    Basically, we start from the beginning of the pcHeader and move to some
    function table offset with a squence of structs that hold each one a
    virtual addresses a another offset.
    From there we move to that second offset and get another struct that holds,
    again, the same virtual address and an index to the beginning
    of the string containing the function's name.
    Function names are null-terminated so we just have to traverse them till
    0x0.
    We do NOT want to read first the function names and blindly associate them
    to the virtual addresses we find at pcHeader['pclnOffset'] because some
    functions simply don't have virtual addresses and I can't really tell why.
    Probably inline functions or something like that...

    I found all information about structs here:
        https://github.com/golang/go/blob/c622d1d3f68369ec5f8ce9694fa27e7acb025004/src/runtime/symtab.go

    @param filename a string for the file name
    '''
    retval = []

    total_data = open(filename, 'rb').read()

    # Get position in file for pcHeader start
    magic_idx = total_data.find(GO116MAGIC)

    # Parse pcHeader, also pcHeader size here is fixed at 64 bytes
    magic, pad1, pad2, minLC, ptrSize, nfunc, nfiles, funcnameOffset,\
                cuOffset,\
                filetabOffset,\
                pctabOffset,\
                pclnOffset = struct.unpack(
                                '<LBBBBQQQQQQQ',
                                total_data[magic_idx:magic_idx+64]
                                )

    # Offset to the first sequence of structures with virtual addresses and
    # index to string representing the function's name...
    fun_offset = magic_idx + pclnOffset

    with open(filename, 'rb') as f:
        f.seek(fun_offset)

        data = f.read()

        index = 0
        fun_index = 0

        while True:
            if fun_index >= nfunc:
                break

            # unpack virtual address and index for the next struct
            addr, idx = struct.unpack('<QQ', data[index:index+16])

            # unpack virtual address and index for the function's name
            addr2, idx2 = struct.unpack('<QI', total_data[fun_offset+idx:fun_offset+idx+12])

            # retrieve function's name
            function_name = ''

            for i in range(magic_idx+64+idx2, magic_idx+64+idx2+cuOffset):
                if total_data[i] == 0:
                    break

                function_name += chr(total_data[i])

            retval.append( (rename_function(function_name), hex(addr2)) )

            index += 16
            fun_index += 1

    return retval

filename = json.loads(r2.cmd('ij'))['core']['file']

functions = get_functions_addresses(filename)

print('Analysing', filename)
r2.cmd('aaa')

for i in functions:
    r2.cmd('af %s %s' % (i[0], i[1]))

print('Done...')
