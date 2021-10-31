
import pefile
import sys
pe = pefile.PE(sys.argv[1])


#check if valid MS Dos header

if pe.DOS_HEADER.e_magic == 0x5a4d:
    FILE_HEADER = pe.NT_HEADERS.FILE_HEADER
    OPTIONAL_HEADER = pe.NT_HEADERS.OPTIONAL_HEADER
    # FILE_HEADER
    Machine = FILE_HEADER.Machine
    NumberOfSections = FILE_HEADER.NumberOfSections
    Characteristics  = FILE_HEADER.Characteristics
    print('**************** FILE_HEADER BEGINS ******************')
    if Machine in pefile.MACHINE_TYPE: print('MACHINE_TYPE: ',pefile.MACHINE_TYPE[Machine])
    print('NumberOfSections ', hex (NumberOfSections))
    print('Characteristics: ', hex(Characteristics))
    if FILE_HEADER.IMAGE_FILE_16BIT_MACHINE: print('    IMAGE_FILE_16BIT_MACHINE')            
    if FILE_HEADER.IMAGE_FILE_32BIT_MACHINE: print('    IMAGE_FILE_32BIT_MACHINE')
    if FILE_HEADER.IMAGE_FILE_AGGRESIVE_WS_TRIM: print('    IMAGE_FILE_AGGRESIVE_WS_TRIM' )
    if FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_HI: print('    IMAGE_FILE_BYTES_REVERSED_HI' )
    if FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_LO: print('    IMAGE_FILE_BYTES_REVERSED_LO' )
    if FILE_HEADER.IMAGE_FILE_DEBUG_STRIPPED: print('    IMAGE_FILE_DEBUG_STRIPPED' )
    if FILE_HEADER.IMAGE_FILE_DLL: print('    IMAGE_FILE_DLL' )
    if FILE_HEADER.IMAGE_FILE_EXECUTABLE_IMAGE: print('    IMAGE_FILE_EXECUTABLE_IMAGE' )
    if FILE_HEADER.IMAGE_FILE_LARGE_ADDRESS_AWARE: print('    IMAGE_FILE_LARGE_ADDRESS_AWARE' )
    if FILE_HEADER.IMAGE_FILE_LINE_NUMS_STRIPPED: print('    IMAGE_FILE_LINE_NUMS_STRIPPED' )
    if FILE_HEADER.IMAGE_FILE_LOCAL_SYMS_STRIPPED: print('    IMAGE_FILE_LOCAL_SYMS_STRIPPED' )
    if FILE_HEADER.IMAGE_FILE_NET_RUN_FROM_SWAP: print('        IMAGE_FILE_NET_RUN_FROM_SWAP' )
    if FILE_HEADER.IMAGE_FILE_RELOCS_STRIPPED: print('        IMAGE_FILE_RELOCS_STRIPPED' )
    if FILE_HEADER.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: print('    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP' )
    if FILE_HEADER.IMAGE_FILE_SYSTEM: print('    IMAGE_FILE_SYSTEM' )
    if FILE_HEADER.IMAGE_FILE_UP_SYSTEM_ONLY: print('    IMAGE_FILE_UP_SYSTEM_ONLY' )
    print('**************** FILE_HEADER ENDS ******************')
    # OPTIONAL_HEADER
    print('**************** OPTIONAL_HEADER BEGINS ******************')
    print('AddressOfEntryPoint: ', hex (OPTIONAL_HEADER.AddressOfEntryPoint)  )                           
    print('BaseOfCode: ', hex (OPTIONAL_HEADER.BaseOfCode) )                                      
    if hasattr(OPTIONAL_HEADER,'BaseOfData'):
       print('BaseOfData: ', hex (OPTIONAL_HEADER.BaseOfData) )                                      
    print('NumberOfRvaAndSizes: ', hex (OPTIONAL_HEADER.NumberOfRvaAndSizes) )
    print('DllCharacteristics: ', hex (OPTIONAL_HEADER.DllCharacteristics   ))
    print('SectionAlignment: ',hex (OPTIONAL_HEADER.SectionAlignment))
    print('FileAlignment',hex (OPTIONAL_HEADER.FileAlignment))
    print('SizeOfCode: ',hex (OPTIONAL_HEADER.SizeOfCode))
    print('SizeOfHeaders: ',hex (OPTIONAL_HEADER.SizeOfHeaders))
    print('SizeOfHeapCommit: ',hex (OPTIONAL_HEADER.SizeOfHeapCommit))
    print('SizeOfHeapReserve: ',hex (OPTIONAL_HEADER.SizeOfHeapReserve))
    print('SizeOfImage: ',hex (OPTIONAL_HEADER.SizeOfImage))
    print('SizeOfInitializedData: ',hex (OPTIONAL_HEADER.SizeOfInitializedData))
    print('SizeOfUninitializedData: ',hex (OPTIONAL_HEADER.SizeOfUninitializedData))
    print('SizeOfStackCommit: ',hex (OPTIONAL_HEADER.SizeOfStackCommit))
    print('SizeOfStackReserve: ',hex (OPTIONAL_HEADER.SizeOfStackReserve))
    print('ImageBase: ',hex (OPTIONAL_HEADER.ImageBase))                                       
    print('Magic: ',hex (OPTIONAL_HEADER.Magic))
    DATA_DIRECTORY = OPTIONAL_HEADER.DATA_DIRECTORY
    DATA_DIRECTORY_NO = 0                                           
    print('DATA_DIRECTORY')
    for dd in DATA_DIRECTORY:
        print('   ',pefile.DIRECTORY_ENTRY[DATA_DIRECTORY_NO],'VirtualAddress: ',
                                                                               hex (dd.VirtualAddress), ' Size: ',hex(dd.Size))
        DATA_DIRECTORY_NO = DATA_DIRECTORY_NO + 1
    print('**************** OPTIONAL_HEADER ENDS ******************')
    print('**************** SECTION_HEADER BEGINS ******************')
    for section in pe.sections:
        print('Name: ',section.Name.decode('utf-8'))  # Name is the bytes object
        print('   VirtualSize: ',hex (section.Misc_VirtualSize))
        print('   VirtualAddress: ',hex (section.VirtualAddress))
        print('   SizeOfRawData: ',hex (section.SizeOfRawData))
        print('   PointerToRawData:  ',hex (section.PointerToRawData))
        print('   PointerToRelocations:  ',hex (section.PointerToRelocations))
        print('   NumberOfRelocations: ' ,hex (section.NumberOfRelocations))
        print('   Characteristics: ',hex (section.Characteristics))
    #imports
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
       ImportDescData = pe.DIRECTORY_ENTRY_IMPORT
       print('************** Imports ******************')
       for idd in ImportDescData:
          print('DLL: ',idd.dll.decode('utf-8'))
          for i in idd.imports: 
              if hasattr(i.name,'decode'):
                 print('   ',i.name.decode('utf-8'),end='')
              print(' ',i.ordinal)
   #exports
    if hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):
       ExportDirData = pe.DIRECTORY_ENTRY_EXPORT
       print('************** Exports ******************')
       print('Name RVA: ',hex (ExportDirData.struct.Name))
       print('   NumberOfFunctions',ExportDirData.struct.NumberOfFunctions)
       print('   Base',ExportDirData.struct.Base) 
       print('AddressOfFunctions: ',hex (ExportDirData.struct.AddressOfFunctions))
       print('AddressOfNameOrdinals: ',hex (ExportDirData.struct.AddressOfNameOrdinals))
       print('AddressOfNames: ',hex (ExportDirData.struct.AddressOfNames))
       print('   Symbols: ')
       for symbol in  ExportDirData.symbols:
          print('      Name: ',symbol.name.decode('utf-8'),' Ordinal: ',symbol.ordinal,' Forwarder: ',symbol.forwarder)
       
    
    
                               


   
else:
    print("Not a valid DOS Header")

