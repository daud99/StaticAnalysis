#!/usr/bin/env python

import pefile
import sys
# pe = pefile.PE(sys.argv[1])

#check if valid MS Dos header
def discoverPE(file):
    file_name = f'pediscover-{file.name}.txt'
    pe = pefile.PE(file.path)
    with open(file_name, 'w') as f:

        if pe.DOS_HEADER.e_magic == 0x5a4d:
            FILE_HEADER = pe.NT_HEADERS.FILE_HEADER
            OPTIONAL_HEADER = pe.NT_HEADERS.OPTIONAL_HEADER
            # FILE_HEADER
            Machine = FILE_HEADER.Machine
            NumberOfSections = FILE_HEADER.NumberOfSections
            Characteristics  = FILE_HEADER.Characteristics
            f.write('**************** FILE_HEADER BEGINS ******************\n')
            if Machine in pefile.MACHINE_TYPE: f.write(f'MACHINE_TYPE: {pefile.MACHINE_TYPE[Machine]}\n')
            f.write(f'NumberOfSections {hex (NumberOfSections)}\n')
            f.write(f'Characteristics: {hex(Characteristics)}\n')
            if FILE_HEADER.IMAGE_FILE_16BIT_MACHINE: f.write('    IMAGE_FILE_16BIT_MACHINE\n')
            if FILE_HEADER.IMAGE_FILE_32BIT_MACHINE: f.write('    IMAGE_FILE_32BIT_MACHINE\n')
            if FILE_HEADER.IMAGE_FILE_AGGRESIVE_WS_TRIM: f.write('    IMAGE_FILE_AGGRESIVE_WS_TRIM\n')
            if FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_HI: f.write('    IMAGE_FILE_BYTES_REVERSED_HI\n')
            if FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_LO: f.write('    IMAGE_FILE_BYTES_REVERSED_LO\n')
            if FILE_HEADER.IMAGE_FILE_DEBUG_STRIPPED: f.write('    IMAGE_FILE_DEBUG_STRIPPED\n')
            if FILE_HEADER.IMAGE_FILE_DLL: f.write('    IMAGE_FILE_DLL\n')
            if FILE_HEADER.IMAGE_FILE_EXECUTABLE_IMAGE: f.write('    IMAGE_FILE_EXECUTABLE_IMAGE\n')
            if FILE_HEADER.IMAGE_FILE_LARGE_ADDRESS_AWARE: f.write('    IMAGE_FILE_LARGE_ADDRESS_AWARE\n')
            if FILE_HEADER.IMAGE_FILE_LINE_NUMS_STRIPPED: f.write('    IMAGE_FILE_LINE_NUMS_STRIPPED\n')
            if FILE_HEADER.IMAGE_FILE_LOCAL_SYMS_STRIPPED: f.write('    IMAGE_FILE_LOCAL_SYMS_STRIPPED\n')
            if FILE_HEADER.IMAGE_FILE_NET_RUN_FROM_SWAP: f.write('        IMAGE_FILE_NET_RUN_FROM_SWAP\n')
            if FILE_HEADER.IMAGE_FILE_RELOCS_STRIPPED: f.write('        IMAGE_FILE_RELOCS_STRIPPED\n')
            if FILE_HEADER.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: f.write('    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP\n')
            if FILE_HEADER.IMAGE_FILE_SYSTEM: f.write('    IMAGE_FILE_SYSTEM\n')
            if FILE_HEADER.IMAGE_FILE_UP_SYSTEM_ONLY: f.write('    IMAGE_FILE_UP_SYSTEM_ONLY\n')
            f.write('**************** FILE_HEADER ENDS ******************\n')
            # OPTIONAL_HEADER
            f.write('**************** OPTIONAL_HEADER BEGINS ******************\n')
            f.write(f'AddressOfEntryPoint: {hex (OPTIONAL_HEADER.AddressOfEntryPoint)}\n')
            f.write(f'BaseOfCode: {hex (OPTIONAL_HEADER.BaseOfCode)}\n')
            if hasattr(OPTIONAL_HEADER,'BaseOfData\n'):
               f.write(f'BaseOfData: {hex (OPTIONAL_HEADER.BaseOfData)}\n')
            f.write(f'NumberOfRvaAndSizes: { hex (OPTIONAL_HEADER.NumberOfRvaAndSizes) }\n')
            f.write(f'DllCharacteristics: {hex (OPTIONAL_HEADER.DllCharacteristics   )}\n')
            f.write(f'SectionAlignment: {hex (OPTIONAL_HEADER.SectionAlignment)}\n')
            f.write(f'FileAlignment {hex (OPTIONAL_HEADER.FileAlignment)}\n')
            f.write(f'SizeOfCode: {hex (OPTIONAL_HEADER.SizeOfCode)}\n')
            f.write(f'SizeOfHeaders: {hex (OPTIONAL_HEADER.SizeOfHeaders)}\n')
            f.write(f'SizeOfHeapCommit: {hex (OPTIONAL_HEADER.SizeOfHeapCommit)}\n')
            f.write(f'SizeOfHeapReserve: {hex (OPTIONAL_HEADER.SizeOfHeapReserve)}\n')
            f.write(f'SizeOfImage: {hex (OPTIONAL_HEADER.SizeOfImage)}\n')
            f.write(f'SizeOfInitializedData: {hex (OPTIONAL_HEADER.SizeOfInitializedData)}\n')
            f.write(f'SizeOfUninitializedData: {hex (OPTIONAL_HEADER.SizeOfUninitializedData)}\n')
            f.write(f'SizeOfStackCommit: {hex (OPTIONAL_HEADER.SizeOfStackCommit)}\n')
            f.write(f'SizeOfStackReserve: {hex (OPTIONAL_HEADER.SizeOfStackCommit)}\n')
            f.write(f'ImageBase: {hex (OPTIONAL_HEADER.ImageBase)}\n')
            f.write(f'Magic: {hex (OPTIONAL_HEADER.Magic)}\n')
            DATA_DIRECTORY = OPTIONAL_HEADER.DATA_DIRECTORY
            DATA_DIRECTORY_NO = 0
            f.write('DATA_DIRECTORY\n')
            for dd in DATA_DIRECTORY:
                f.write(f' {pefile.DIRECTORY_ENTRY[DATA_DIRECTORY_NO]} VirtualAddress: {hex (dd.VirtualAddress)} Size: {hex(dd.Size)}\n')
                DATA_DIRECTORY_NO = DATA_DIRECTORY_NO + 1
            f.write('**************** OPTIONAL_HEADER ENDS ******************\n')
            f.write('**************** SECTION_HEADER BEGINS ******************\n')
            for section in pe.sections:
                f.write(f"Name: {section.Name.decode('utf-8')}")  # Name is the bytes object
                f.write(f'VirtualSize: {hex (section.Misc_VirtualSize)}\n')
                f.write(f'VirtualAddress: {hex (section.VirtualAddress)}\n')
                f.write(f'SizeOfRawData: {hex (section.SizeOfRawData)}\n')
                f.write(f'PointerToRawData:  {hex (section.PointerToRawData)}\n')
                f.write(f'PointerToRelocations:  {hex (section.PointerToRelocations)}\n')
                f.write(f'NumberOfRelocations: {hex (section.NumberOfRelocations)}\n')
                f.write(f'Characteristics: {hex (section.Characteristics)}\n')
            #imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT\n'):
               ImportDescData = pe.DIRECTORY_ENTRY_IMPORT
               f.write('************** Imports ******************\n')
               for idd in ImportDescData:
                  f.write(f'DLL: {idd.dll.decode("utf-8")}\n')
                  for i in idd.imports:
                      if hasattr(i.name,'decode\n'):
                         f.write(f'{i.name.decode("utf-8")}\n')
                      f.write(f'{i.ordinal} \n')
           #exports
            if hasattr(pe,'DIRECTORY_ENTRY_EXPORT\n'):
               ExportDirData = pe.DIRECTORY_ENTRY_EXPORT
               f.write('************** Exports ******************\n')
               f.write(f'Name RVA: {hex (ExportDirData.struct.Name)}\n')
               f.write(f'   NumberOfFunctions {ExportDirData.struct.NumberOfFunctions}\n')
               f.write(f'   Base {ExportDirData.struct.Base}\n')
               f.write(f'AddressOfFunctions: {hex (ExportDirData.struct.AddressOfFunctions)}\n')
               f.write(f'AddressOfNameOrdinals: {hex (ExportDirData.struct.AddressOfNameOrdinals)}\n')
               f.write(f'AddressOfNames: {hex (ExportDirData.struct.AddressOfNames)}\n')
               f.write('   Symbols: \n')
               for symbol in  ExportDirData.symbols:
                  f.write(f'      Name: {symbol.name.decode("utf - 8")} Ordinal: {symbol.ordinal} Forwarder: {symbol.forwarder}\n')







        else:
            print("Not a valid DOS Header")

