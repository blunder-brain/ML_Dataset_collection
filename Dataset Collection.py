import pefile
import json
import os
def get_pe_info(exe_path):
    pe = pefile.PE(exe_path)
    
    
    pe_info = {}

    # DOS_HEADER
    pe_info['e_magic'] = pe.DOS_HEADER.e_magic
    pe_info['e_cblp'] = pe.DOS_HEADER.e_cblp
    pe_info['e_cp'] = pe.DOS_HEADER.e_cp
    pe_info['e_crlc'] = pe.DOS_HEADER.e_crlc
    pe_info['e_cparhdr'] = pe.DOS_HEADER.e_cparhdr
    pe_info['e_minalloc'] = pe.DOS_HEADER.e_minalloc
    pe_info['e_maxalloc'] = pe.DOS_HEADER.e_maxalloc
    pe_info['e_ss'] = pe.DOS_HEADER.e_ss
    pe_info['e_sp'] = pe.DOS_HEADER.e_sp
    pe_info['e_csum'] = pe.DOS_HEADER.e_csum
    pe_info['e_ip'] = pe.DOS_HEADER.e_ip
    pe_info['e_cs'] = pe.DOS_HEADER.e_cs
    pe_info['e_lfarlc'] = pe.DOS_HEADER.e_lfarlc
    pe_info['e_ovno'] = pe.DOS_HEADER.e_ovno
    pe_info['e_oemid'] = pe.DOS_HEADER.e_oemid
    pe_info['e_oeminfo'] = pe.DOS_HEADER.e_oeminfo
    pe_info['e_lfanew'] = pe.DOS_HEADER.e_lfanew

    # FILE_HEADER
    pe_info['Machine'] = pe.FILE_HEADER.Machine
    pe_info['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
    pe_info['TimeDateStamp'] = pe.FILE_HEADER.TimeDateStamp
    pe_info['PointerToSymbolTable'] = pe.FILE_HEADER.PointerToSymbolTable
    pe_info['NumberOfSymbols'] = pe.FILE_HEADER.NumberOfSymbols
    pe_info['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    pe_info['Characteristics'] = pe.FILE_HEADER.Characteristics

    # OPTIONAL_HEADER
    pe_info['Magic'] = pe.OPTIONAL_HEADER.Magic
    pe_info['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    pe_info['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    pe_info['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    pe_info['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    pe_info['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    pe_info['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    pe_info['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    pe_info['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    pe_info['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    pe_info['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    pe_info['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    pe_info['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    pe_info['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    pe_info['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    pe_info['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    pe_info['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    pe_info['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    pe_info['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    pe_info['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    pe_info['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    pe_info['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    pe_info['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    pe_info['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    pe_info['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    pe_info['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    pe_info['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    pe_info['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
    
    # Sections

    standardSectionNames = [".text", ".bss", ".rdata", ".data", ".idata", ".reloc", ".rsrc"]

    SuspiciousNameSections = 0

    for section in pe.sections:
        section_name = section.Name.decode().rstrip('\x00')
        if section_name not in standardSectionNames:
            SuspiciousNameSections += 1



    suspiciousImportFunctions = ["CreateProcess", "OpenProcess", "WriteProcessMemory", "CreateRemoteThread", "ReadProcessMemory", "CreateFile", "RegSetValue", "RegCreateKey", "RegDeleteKey", "RegDeleteValue", "RegOpenKey", "RegQueryValue", "RegSetValue", "RegEnumValue", "WinExec", "ShellExecute", "HttpSendRequest", "InternetReadFile", "InternetConnect", "InternetOpen", "InternetOpenUrl", "InternetCrackUrl", "InternetSetOption"]

    SuspiciousImportFunctions = 0

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name.decode() in suspiciousImportFunctions:
                SuspiciousImportFunctions += 1


    pe_info['SuspiciousImportFunctions'] = SuspiciousImportFunctions
    pe_info['SuspiciousNameSection'] = SuspiciousNameSections          
    pe_info['SectionsLength'] = len(pe.sections)
    pe_info['SectionMinEntropy'] = min(section.get_entropy() for section in pe.sections)
    pe_info['SectionMaxEntropy'] = max(section.get_entropy() for section in pe.sections)
    pe_info['SectionMinRawsize'] = min(section.SizeOfRawData for section in pe.sections)
    pe_info['SectionMaxRawsize'] = max(section.SizeOfRawData for section in pe.sections)
    pe_info['SectionMinVirtualsize'] = min(section.Misc_VirtualSize for section in pe.sections)
    pe_info['SectionMaxVirtualsize'] = max(section.Misc_VirtualSize for section in pe.sections)
    pe_info['SectionMaxPhysical'] = max(section.PointerToRawData for section in pe.sections)
    pe_info['SectionMinPhysical'] = min(section.PointerToRawData for section in pe.sections)
    pe_info['SectionMaxVirtual'] = max(section.VirtualAddress for section in pe.sections)
    pe_info['SectionMinVirtual'] = min(section.VirtualAddress for section in pe.sections)
    pe_info['SectionMaxPointerData'] = max(section.PointerToRawData for section in pe.sections)
    pe_info['SectionMinPointerData'] = min(section.PointerToRawData for section in pe.sections)
    pe_info['SectionMaxChar'] = max(section.Characteristics for section in pe.sections)
    pe_info['SectionMainChar'] = min(section.Characteristics for section in pe.sections)

    # Directories
    pe_info['DirectoryEntryImport'] = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
    pe_info['DirectoryEntryImportSize'] = sum(len(i.imports) for i in pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
    pe_info['DirectoryEntryExport'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
    pe_info['ImageDirectoryEntryExport'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].Size
    pe_info['ImageDirectoryEntryImport'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].Size
    pe_info['ImageDirectoryEntryResource'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].Size
    pe_info['ImageDirectoryEntryException'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']].Size
    pe_info['ImageDirectoryEntrySecurity'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

    
    return pe_info

def write_to_file(file_path, data):
    with open(file_path, 'w') as f:
        f.write(json.dumps(data, indent=4))

def main():
    directory_path = r'E:\Shared\EXE'  
    output_file_path = r'D:\SIH\Output.txt'  
    all_pe_info = {}
    for filename in os.listdir(directory_path):
        if filename.endswith(".exe"):
            exe_path = os.path.join(directory_path, filename)
            pe_info = get_pe_info(exe_path)
            all_pe_info[filename] = pe_info  # Use filename as key

    write_to_file(output_file_path, all_pe_info)

if __name__ == '__main__':
    main()
