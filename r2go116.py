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

def find_magic(filename: str):
    '''
    @brief find the index where the go magic is at
    @param filename a string for filename
    @return integer for the magic's position in the file
    '''
    with open(filename, 'rb') as f:
        data = f.read()

        magic_idx = data.find(GO116MAGIC)

        if magic_idx < 0:
            print('No magic, is it a go binary compiled with go >= 1.16?')

            exit(-1)

        return magic_idx

def get_pcHeader(filename: str, magic_idx: int):
    '''
    @brief get the pcHeader
    @param filename a string for filename
    @param magic_idx an integer for the index where magic number's at
    @return dict with all fields of pcHeader structure
    '''
    with open(filename, 'rb') as f:
        f.seek(magic_idx)

        data = f.read()

        magic, pad1, pad2, minLC, ptrSize, nfunc, nfiles, funcnameOffset, cuOffset, filetabOffset, pctabOffset, pclnOffset = struct.unpack('<LBBBBQQQQQQQ', data[:64])

        return {
            'magic': magic,
            'pad1': pad1,
            'pad2': pad2,
            'minLC': minLC,
            'ptrSize': ptrSize,
            'nfunc': nfunc,
            'nfiles': nfiles,
            'funcnameOffset': funcnameOffset,
            'cuOffset': cuOffset,
            'filetabOffset': filetabOffset,
            'pctabOffset': pctabOffset,
            'pclnOffset': pclnOffset
        }

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

def get_functions_addresses(filename: str, magic_idx: int, pcHeader: dict):
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
    @param magic_idx an integer for the magic number's position in the file
    @param pcHeader a dict with all the pcHeader information
    '''
    retval = []

    # Offset to the first sequence of structures with virtual addresses and
    # index to string representing the function's name...
    fun_offset = magic_idx + pcHeader['pclnOffset']

    total_data = open(filename, 'rb').read()

    with open(filename, 'rb') as f:
        f.seek(fun_offset)

        data = f.read()

        index = 0
        fun_index = 0

        while True:
            # unpack virtual address and index for the next struct
            addr, idx = struct.unpack('<QQ', data[index:index+16])

            try:
                # unpack virtual address and index for the function's name
                addr2, idx2 = struct.unpack('<QI', total_data[fun_offset+idx:fun_offset+idx+12])

                # retrieve function's name 
                function_name = ''

                for i in range(magic_idx+64+idx2, magic_idx+64+idx2+1000):
                    if total_data[i] == 0:
                        break

                    function_name += chr(total_data[i])

                retval.append( (rename_function(function_name), hex(addr2)) )
            ##
            # TODO: this is not the best choice, I should probably calculate the size of the
            # whole table and go only through that chunk. I should fix this
            #
            except Exception as e:
                break

            index += 16
            fun_index += 1

    return retval

filename = json.loads(r2.cmd('ij'))['core']['file']

magic_idx = find_magic(filename)
pc_header = get_pcHeader(filename, magic_idx)
functions = get_functions_addresses(filename, magic_idx, pc_header)

print('Analysing %s', filename)
r2.cmd('aaa')

for i in functions:
    r2.cmd('af %s %s' % (i[0], i[1]))

print('Done...')
