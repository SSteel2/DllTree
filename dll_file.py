# Major notes for this:
# https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg
# https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format
from pathlib import Path
import time


class DllFile:
    """docstring for NativeDll"""
    is_initialized = False
    is_verbose = False

    def __init__(self, filename):
        """Opens dll file and prepares for reading."""
        file_path = Path(filename)
        if file_path.is_file():
            self.dll_file = open(filename, "rb")
        else:
            print(filename, "is not a valid file path")
            return
        dos_header = self.dll_file.read(2)
        if dos_header != b'\x4d\x5a':
            print("Not an PE format file")
            self.dll_file.close()
            return
        self.is_initialized = True

    def ReadDll(self):
        """Parses dll file into logical blocks.
        This method reads the main header."""
        if not self.is_initialized:
            return

        # Seek to 0x3C, where pointer to PE header should be
        self.dll_file.seek(0x3C)
        pointer_pe_header = int(self.dll_file.read(4)[::-1].hex(), 16)
        self.dll_file.seek(pointer_pe_header)

        # Read signature
        pe_header = self.dll_file.read(4)
        if pe_header != b'PE\x00\x00':
            print("Missing PE Signature")
            return
        if self.is_verbose:
            print("[INFO] PE Signature found")

        # Read Machine version
        self.__ReadMachineVersion()

        # Read number of sections
        self.number_sections = int(self.dll_file.read(2)[::-1].hex(), 16)
        if self.is_verbose:
            print("Number of sections:", self.number_sections)

        # Timestamp file created
        file_created_timestamp = int(self.dll_file.read(4)[::-1].hex(), 16)
        if self.is_verbose:
            print("Time created:", time.ctime(file_created_timestamp))

        # skip deprecated bytes
        self.dll_file.seek(8, 1)

        # size of optional header
        self.optional_header_size = int(self.dll_file.read(2)[::-1].hex(), 16)

        # Read characteristics
        self.__ReadCharacteristics()

        self.__ReadOptionalHeader()
        self.__ReadOptionalHeaderWindows()
        self.__ReadRvaAndSizes()
        self.__ReadSectionHeaders()

    def __ReadOptionalHeader(self):
        """Reads Optional Header Standard fields."""
        magic = self.dll_file.read(2)
        self.magic_type = None
        if magic == b'\x0b\x02':
            if self.is_verbose:
                print("File type is PE32+")
            self.magic_type = 'PE32+'
        elif magic == b'\x0b\x01':
            if self.is_verbose:
                print("File type is PE32")
            self.magic_type = 'PE32'

        self.major_linker_version = int(self.dll_file.read(1).hex(), 16)
        self.minor_linker_version = int(self.dll_file.read(1).hex(), 16)
        if self.is_verbose:
            print(f"Linker version: {self.major_linker_version}.{self.minor_linker_version}")
        self.size_of_code = int(self.dll_file.read(4)[::-1].hex(), 16)
        self.size_of_initialized_data = int(self.dll_file.read(4)[::-1].hex(), 16)
        self.size_of_uninitialized_data = int(self.dll_file.read(4)[::-1].hex(), 16)
        self.address_of_entry_point = int(self.dll_file.read(4)[::-1].hex(), 16)
        self.base_of_code = int(self.dll_file.read(4)[::-1].hex(), 16)
        if self.magic_type == 'PE32':
            self.base_of_data = int(self.dll_file.read(4)[::-1].hex(), 16)

    def __ReadOptionalHeaderWindows(self):
        """Reads Optional Header Windows specific fields."""
        self.image_base = int(self.dll_file.read(4 if self.magic_type == 'PE32' else 8)[::-1].hex(), 16)
        self.section_alignment = int(self.dll_file.read(4)[::-1].hex(), 16)
        self.file_alignment = int(self.dll_file.read(4)[::-1].hex(), 16)
        self.major_operating_system_version = int(self.dll_file.read(2)[::-1].hex(), 16)
        self.minor_operating_system_version = int(self.dll_file.read(2)[::-1].hex(), 16)
        if self.is_verbose:
            print(f"Operating system version: {self.major_operating_system_version}.{self.minor_operating_system_version}")
        self.major_image_version = int(self.dll_file.read(2)[::-1].hex(), 16)
        self.minor_image_version = int(self.dll_file.read(2)[::-1].hex(), 16)
        if self.is_verbose:
            print(f"Image version: {self.major_image_version}.{self.minor_image_version}")
        self.major_subsystem_version = int(self.dll_file.read(2)[::-1].hex(), 16)
        self.minor_subsystem_version = int(self.dll_file.read(2)[::-1].hex(), 16)
        if self.is_verbose:
            print(f"Subsystem version: {self.major_subsystem_version}.{self.minor_subsystem_version}")
        win32_version_value = int(self.dll_file.read(4)[::-1].hex(), 16)
        if win32_version_value != 0:
            print(f"Error during optional header read. Win32 Version Value is a reserved field, must be 0.")
        self.size_of_image = int(self.dll_file.read(4)[::-1].hex(), 16)
        if self.is_verbose:
            print(f"File size: {self.size_of_image}")  # TODO make this print more meaningful
        self.size_of_headers = int(self.dll_file.read(4)[::-1].hex(), 16)
        self.check_sum = int(self.dll_file.read(4)[::-1].hex(), 16)
        self.subsystem = int(self.dll_file.read(2)[::-1].hex(), 16)
        self.dll_characteristics = int(self.dll_file.read(2)[::-1].hex(), 16)  # TODO: properly extract this information
        self.size_of_stack_reserve = int(self.dll_file.read(4 if self.magic_type == 'PE32' else 8)[::-1].hex(), 16)
        self.size_of_stack_commit = int(self.dll_file.read(4 if self.magic_type == 'PE32' else 8)[::-1].hex(), 16)
        self.size_of_heap_reserve = int(self.dll_file.read(4 if self.magic_type == 'PE32' else 8)[::-1].hex(), 16)
        self.size_of_heap_commit = int(self.dll_file.read(4 if self.magic_type == 'PE32' else 8)[::-1].hex(), 16)
        loader_flags = int(self.dll_file.read(4)[::-1].hex(), 16)
        if loader_flags != 0:
            print("Error during optional header read. Loader flags is a reserved field, must be 0.")
        self.number_of_rva_and_sizes = int(self.dll_file.read(4)[::-1].hex(), 16)
        if self.number_of_rva_and_sizes != 16:
            print("[WARNING] Only files with 16 RVA tables are properly supported")

    def __ReadRvaAndSizes(self):
        """Reads RVA tables and sizes."""
        rva_table = []
        for i in range(self.number_of_rva_and_sizes):
            rva_table.append((int(self.dll_file.read(4)[::-1].hex(), 16), int(self.dll_file.read(4)[::-1].hex(), 16)))
        rva_names = ["ExportTable", "ImportTable", "ResourceTable", "ExceptionTable", "CertificateTable",
                     "BaseRelocationTable", "RvaDebug", "RvaArchitecture", "RvaGlobalPtr", "ThreadLocalStorageTable",
                     "LoadConfigTable", "BoundImport", "ImportAddressTable", "DelayImportDescriptor",
                     "ClrRuntimeHeader", "RvaReserved"]
        if self.number_of_rva_and_sizes == len(rva_names):
            self.rva = dict(zip(rva_names, rva_table))
        elif self.number_of_rva_and_sizes < len(rva_names):
            self.rva = dict(zip(rva_names[:self.number_of_rva_and_sizes - 1],
                                rva_table[:self.number_of_rva_and_sizes - 1]))
            self.rva[rva_names[-1]] = rva_table[-1]
        elif self.number_of_rva_and_sizes > len(rva_names):
            self.rva = dict(zip(rva_names[:len(rva_names) - 1], rva_table[:len(rva_names) - 1]))
            unknown_values = self.number_of_rva_and_sizes - len(rva_names)
            self.rva.update(dict(zip(["Unknown" + str(i) for i in range(unknown_values)],
                                     rva_table[len(rva_names) - 1: len(rva_table) - 1])))
            self.rva[rva_names[-1]] = rva_table[-1]

        if self.rva["RvaArchitecture"][0] != 0 or self.rva["RvaArchitecture"][1] != 0:
            print("Error during RVA Tables and sizes read. Architecture is a reserved field, must be 0.")
        if self.rva["RvaGlobalPtr"][1] != 0:
            print("Error during RVA Tables and sizes read. GlobalPtr size must be 0.")
        if self.rva["RvaReserved"][0] != 0 or self.rva["RvaReserved"][0] != 0:
            print("Error during RVA Tables and sizes read. Reserved field must be 0.")

    def __ReadSectionHeaders(self):
        """Reads Section table (Section headers)."""
        self.section_headers = []
        for i in range(1, self.number_sections + 1):  # They are numbered starting from 1
            section_header = dict()
            section_header['Name'] = self.dll_file.read(8).decode("ANSI").rstrip('\0')
            section_header['VirtualSize'] = int(self.dll_file.read(4)[::-1].hex(), 16)
            section_header['VirtualAddress'] = int(self.dll_file.read(4)[::-1].hex(), 16)
            section_header['SizeOfRawData'] = int(self.dll_file.read(4)[::-1].hex(), 16)
            section_header['PointerToRawData'] = int(self.dll_file.read(4)[::-1].hex(), 16)
            section_header['PointerToRelocations'] = int(self.dll_file.read(4)[::-1].hex(), 16)
            section_header['PointerToLineNumbers'] = int(self.dll_file.read(4)[::-1].hex(), 16)
            section_header['NumberOfRelocations'] = int(self.dll_file.read(2)[::-1].hex(), 16)
            section_header['NumberOfLineNumbers'] = int(self.dll_file.read(2)[::-1].hex(), 16)
            section_header['Characteristics'] = int(self.dll_file.read(4)[::-1].hex(), 16)
            self.section_headers.append(section_header)

    def ReadDllDependencies(self):
        """Reads dll dependency information."""

        if not self.is_initialized:
            return

        # Dll's are located in import table
        # First we need to get the section of import table
        import_table_section = None
        for header in self.section_headers:
            if header['VirtualAddress'] <= self.rva["ImportTable"][0] and \
                    header['VirtualAddress'] + header['SizeOfRawData'] > self.rva["ImportTable"][0]:
                import_table_section = header
                break
        # Using section data calculate real address of import table
        import_table_real_address = self.rva["ImportTable"][0] - import_table_section['VirtualAddress'] + \
            import_table_section['PointerToRawData']
        # This address points to Image import descriptor (winnt.h, 17643)
        # This structure contains:
        # union {
        #     DWORD   Characteristics;            // 0 for terminating null import descriptor
        #     DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
        # } DUMMYUNIONNAME;
        # DWORD   TimeDateStamp;                  // 0 if not bound,
        #                                         // -1 if bound, and real date\time stamp
        #                                         //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
        #                                         // O.W. date/time stamp of DLL bound to (Old BIND)
        # DWORD   ForwarderChain;                 // -1 if no forwarders
        # DWORD   Name;
        # DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
        self.dll_file.seek(import_table_real_address, 0)
        self.image_import_descriptors = []
        while True:
            image_import_descriptor = dict()
            image_import_descriptor['Characteristics'] = int(self.dll_file.read(4)[::-1].hex(), 16)
            image_import_descriptor['TimeDateStamp'] = int(self.dll_file.read(4)[::-1].hex(), 16)
            image_import_descriptor['ForwarderChain'] = int(self.dll_file.read(4)[::-1].hex(), 16)
            image_import_descriptor['Name'] = int(self.dll_file.read(4)[::-1].hex(), 16)
            image_import_descriptor['FirstThunk'] = int(self.dll_file.read(4)[::-1].hex(), 16)
            # If characteristics is 0 then it means we have reached the end of the table
            if image_import_descriptor['Characteristics'] == 0:
                break
            self.image_import_descriptors.append(image_import_descriptor)

        # Get image import descriptor names
        for descriptor in self.image_import_descriptors:
            descriptor_name_address = descriptor['Name'] - import_table_section['VirtualAddress'] + \
                import_table_section['PointerToRawData']
            self.dll_file.seek(descriptor_name_address, 0)
            name = self.dll_file.read(100)  # I hope that 100 symbols is enough for dll name
            descriptor['RealName'] = name.decode('ANSI')[:name.decode('ANSI').find('\x00')]

        # Print dll dependencies
        if self.is_verbose:
            print("Dll dependencies:")
            for descriptor in self.image_import_descriptors:
                print(f"\t{descriptor['RealName']}")

    def __ReadMachineVersion(self):
        """Reads Machine version."""
        machine = int(self.dll_file.read(2).hex(), 16)
        if machine == 0x6486:
            print("64-bit executable")

        machine_types = {
            0x0000: ("UNKNOWN", "The contents of this field are assumed to be applicable to any machine type"),
            0xd301: ("AM33", "Matsushita AM33"),
            0x6486: ("AMD64", "x64"),
            0xc001: ("ARM", "ARM little endian"),
            0x64aa: ("ARM64", "ARM64 little endian"),
            0xc401: ("ARMNT", "ARM Thumb-2 little endian"),
            0xbc0e: ("EBC", "EFI byte code"),
            0x4c01: ("I386", "Intel 386 or later processors and compatible processors"),
            0x0002: ("IA64", "Intel Itanium processor family"),
            0x4190: ("M32R", "Mitsubishi M32R little endian"),
            0x6602: ("MIPS16", "MIPS16"),
            0x6603: ("MIPSFPU", "MIPS with FPU"),
            0x6604: ("MIPSFPU16", "MIPS16 with FPU"),
            0xf001: ("POWERPC", "Power PC little endian"),
            0xf101: ("POWERPCFP", "Power PC with floating point support"),
            0x6601: ("R4000", "MIPS little endian"),
            0x3250: ("RISCV32", "RISC-V 32-bit address space"),
            0x6450: ("RISCV64", "RISC-V 64-bit address space"),
            0x2851: ("RISCV128", "RISC-V 128-bit address space"),
            0xa201: ("SH3", "Hitachi SH3"),
            0xa301: ("SH3DSP", "Hitachi SH3 DSP"),
            0xa601: ("SH4", "Hitachi SH4"),
            0xa801: ("SH5", "Hitachi SH5"),
            0xc201: ("THUMB", "Thumb"),
            0x6901: ("WCEMIPSV2", "MIPS little-endian WCE v2")}

        if machine not in machine_types:
            print("[ERROR] Unknown machine type")
            return
        self.machine_type = machine_types[machine]
        if self.is_verbose:
            print(f"Machine type: {self.machine_type[0]}, {self.machine_type[1]}")
        else:
            print(f"Machine type: {self.machine_type[0]}")

    def __ReadCharacteristics(self):
        """Reads characteristics values."""
        self.characteristics_bitflag = int(self.dll_file.read(2)[::-1].hex(), 16)

        characteristics_flags = {
            0x0001: ("RELOCS_STRIPPED", "Image only, Windows CE, and Microsoft Windows NT and later. This "
                     "indicates that the file does not contain base relocations and must therefore be loaded at its "
                     "preferred base address. If the base address is not available, the loader reports an error. The "
                     "default behavior of the linker is to strip base relocations from executable (EXE) files."),
            0x0002: ("EXECUTABLE_IMAGE", "Image only. This indicates that the image file is valid and can "
                     "be run. If this flag is not set, it indicates a linker error."),
            0x0020: ("LARGE_ADDRESS_AWARE", "Application can handle > 2-GB addresses."),
            0x0100: ("32BIT_MACHINE", "Machine is based on a 32-bit-word architecture."),
            0x0200: ("DEBUG_STRIPPED", "Debugging information is removed from the image file."),
            0x0400: ("REMOVABLE_RUN_FROM_SWAP", "If the image is on removable media, fully load it and "
                     "copy it to the swap file."),
            0x0800: ("NET_RUN_FROM_SWAP", "If the image is on network media, fully load it and copy it to "
                     "the swap file."),
            0x1000: ("SYSTEM", "The image file is a system file, not a user program."),
            0x2000: ("DLL", "The image file is a dynamic-link library (DLL). Such files are considered "
                     "executable files for almost all purposes, although they cannot be directly run."),
            0x4000: ("UP_SYSTEM_ONLY", "The file should be run only on a uniprocessor machine.")}
        error_flags = {
            0x0004: ("LINE_NUMS_STRIPPED", "COFF line numbers have been removed. This flag is deprecated "
                     "and should be zero."),
            0x0008: ("LOCAL_SYMS_STRIPPED", "COFF symbol table entries for local symbols have been "
                     "removed. This flag is deprecated and should be zero."),
            0x0010: ("AGGRESSIVE_WS_TRIM", "Obsolete. Aggressively trim working set. This flag is "
                     "deprecated for Windows 2000 and later and must be zero."),
            0x0080: ("BYTES_REVERSED_LO", "Little endian: the least significant bit (LSB) precedes the "
                     "most significant bit (MSB) in memory. This flag is deprecated and should be zero."),
            0x8000: ("BYTES_REVERSED_HI", "Big endian: the MSB precedes the LSB in memory. This flag is "
                     "deprecated and should be zero.")}

        for flag in error_flags:
            if self.characteristics_bitflag & flag != 0:
                print(f"[ERROR] Obsolete flag {error_flags[flag][0]} set to non-zero")

        print("Characteristics:")
        for flag in characteristics_flags:
            if self.characteristics_bitflag & flag != 0:
                if self.is_verbose:
                    print(f"\t{characteristics_flags[flag][0]} {characteristics_flags[flag][1]}")
                else:
                    print(f"\t{characteristics_flags[flag][0]}")


if __name__ == '__main__':
    dll = DllFile("Test/SQLite2.dll")
    dll.is_verbose = True
    dll.ReadDll()
    dll.ReadDllDependencies()
