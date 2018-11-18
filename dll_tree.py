# Major notes for this:
# https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg
# https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format
import time

dll_file = open("Test/SQLite2.dll", "rb")

dos_header = dll_file.read(2)
if dos_header != b'\x4d\x5a':
    print("Not an PE format file")

# Seek to 0x3C, where pointer to PE header should be
dll_file.seek(0x3C)
pointer_pe_header_bytes = dll_file.read(4)
pointer_pe_header = int(pointer_pe_header_bytes[::-1].hex(), 16)
dll_file.seek(pointer_pe_header)
# Read signature
pe_header = dll_file.read(4)
if pe_header != b'PE\x00\x00':
    print("Missing PE Signature")

# Read Machine version
machine = dll_file.read(2)
machine = int(machine.hex(), 16)
if machine == 0x6486:
    print("64-bit executable")

# Red number of sections
number_sections = dll_file.read(2)
number_sections = int(number_sections[::-1].hex(), 16)

# Timestamp file created
file_created_timestamp = dll_file.read(4)
file_created_timestamp = int(file_created_timestamp[::-1].hex(), 16)
print("Time created:", time.ctime(file_created_timestamp))

# skip deprecated bytes
dll_file.seek(8, 1)

# size of optional header
optional_header_size = dll_file.read(2)
optional_header_size = int(optional_header_size[::-1].hex(), 16)

# characteristics, will need to be handled by a table
characteristics_bitflag = dll_file.read(2)
characteristics_bitflag = int(characteristics_bitflag[::-1].hex(), 16)

# Optional Header Standard fields
magic = dll_file.read(2)
magic_type = None
if magic == b'\x0b\x02':
    print("File type is PE32+")
    magic_type = 'PE32+'
elif magic == b'\x0b\x01':
    print("File type is PE32 (unsupported)")
    magic_type = 'PE32'

major_linker_version = int(dll_file.read(1).hex(), 16)
minor_linker_version = int(dll_file.read(1).hex(), 16)
size_of_code = int(dll_file.read(4)[::-1].hex(), 16)
size_of_initialized_data = int(dll_file.read(4)[::-1].hex(), 16)
size_of_uninitialized_data = int(dll_file.read(4)[::-1].hex(), 16)
address_of_entry_point = int(dll_file.read(4)[::-1].hex(), 16)
base_of_code = int(dll_file.read(4)[::-1].hex(), 16)
if magic_type == 'PE32':
    base_of_data = int(dll_file.read(4)[::-1].hex(), 16)

# Optional Header Windows specific fields
image_base = int(dll_file.read(4 if magic_type == 'PE32' else 8)[::-1].hex(), 16)
section_alignment = int(dll_file.read(4)[::-1].hex(), 16)
file_alignment = int(dll_file.read(4)[::-1].hex(), 16)
major_operating_system_version = int(dll_file.read(2)[::-1].hex(), 16)
minor_operating_system_version = int(dll_file.read(2)[::-1].hex(), 16)
major_image_version = int(dll_file.read(2)[::-1].hex(), 16)
minor_image_version = int(dll_file.read(2)[::-1].hex(), 16)
major_subsystem_version = int(dll_file.read(2)[::-1].hex(), 16)
minor_subsystem_version = int(dll_file.read(2)[::-1].hex(), 16)
win32_version_value = int(dll_file.read(4)[::-1].hex(), 16)
if win32_version_value != 0:
    print("Error during optional header read. Win32 Version Value is a reserved field, must be 0.")
size_of_image = int(dll_file.read(4)[::-1].hex(), 16)
size_of_headers = int(dll_file.read(4)[::-1].hex(), 16)
check_sum = int(dll_file.read(4)[::-1].hex(), 16)
subsystem = int(dll_file.read(2)[::-1].hex(), 16)
dll_characteristics = int(dll_file.read(2)[::-1].hex(), 16)
size_of_stack_reserve = int(dll_file.read(4 if magic_type == 'PE32' else 8)[::-1].hex(), 16)
size_of_stack_commit = int(dll_file.read(4 if magic_type == 'PE32' else 8)[::-1].hex(), 16)
size_of_heap_reserve = int(dll_file.read(4 if magic_type == 'PE32' else 8)[::-1].hex(), 16)
size_of_heap_commit = int(dll_file.read(4 if magic_type == 'PE32' else 8)[::-1].hex(), 16)
loader_flags = int(dll_file.read(4)[::-1].hex(), 16)
if loader_flags != 0:
    print("Error during optional header read. Loader flags is a reserved field, must be 0.")
number_of_rva_and_sizes = int(dll_file.read(4)[::-1].hex(), 16)
if number_of_rva_and_sizes != 16:
    print("Only files with 16 RVA tables are supported")

# RVA tables and sizes
export_table = int(dll_file.read(4)[::-1].hex(), 16)
export_table_size = int(dll_file.read(4)[::-1].hex(), 16)
import_table = int(dll_file.read(4)[::-1].hex(), 16)
import_table_size = int(dll_file.read(4)[::-1].hex(), 16)
resource_table = int(dll_file.read(4)[::-1].hex(), 16)
resource_table_size = int(dll_file.read(4)[::-1].hex(), 16)
exception_table = int(dll_file.read(4)[::-1].hex(), 16)
exception_table_size = int(dll_file.read(4)[::-1].hex(), 16)
certificate_table = int(dll_file.read(4)[::-1].hex(), 16)
certificate_table_size = int(dll_file.read(4)[::-1].hex(), 16)
base_relocation_table = int(dll_file.read(4)[::-1].hex(), 16)
base_relocation_table_size = int(dll_file.read(4)[::-1].hex(), 16)
rva_debug = int(dll_file.read(4)[::-1].hex(), 16)
rva_debug_size = int(dll_file.read(4)[::-1].hex(), 16)
rva_architecture = int(dll_file.read(8)[::-1].hex(), 16)
if rva_architecture != 0:
    print("Error during RVA Tables and sizes read. Architecture is a reserved field, must be 0.")
rva_global_ptr = int(dll_file.read(4)[::-1].hex(), 16)
rva_global_ptr_size = int(dll_file.read(4)[::-1].hex(), 16)
if rva_global_ptr_size != 0:
    print("Error during RVA Tables and sizes read. GlobalPtr size must be 0.")
thread_local_storage_table = int(dll_file.read(4)[::-1].hex(), 16)
thread_local_storage_table_size = int(dll_file.read(4)[::-1].hex(), 16)
load_config_table = int(dll_file.read(4)[::-1].hex(), 16)
load_config_table_size = int(dll_file.read(4)[::-1].hex(), 16)
bound_import = int(dll_file.read(4)[::-1].hex(), 16)
bound_import_size = int(dll_file.read(4)[::-1].hex(), 16)
import_adress_table = int(dll_file.read(4)[::-1].hex(), 16)
import_adress_table_size = int(dll_file.read(4)[::-1].hex(), 16)
delay_import_descriptor = int(dll_file.read(4)[::-1].hex(), 16)
delay_import_descriptor_size = int(dll_file.read(4)[::-1].hex(), 16)
clr_runtime_header = int(dll_file.read(4)[::-1].hex(), 16)
clr_runtime_header_size = int(dll_file.read(4)[::-1].hex(), 16)
rva_reserved = int(dll_file.read(8)[::-1].hex(), 16)
if rva_reserved != 0:
    print("Error during RVA Tables and sizes read. Reserved field must be 0.")

# Section table (Section headers)
section_headers = []
for i in range(1, number_sections + 1):  # They are numbered starting from 1
    section_header = dict()
    section_header['Name'] = dll_file.read(8).decode("ANSI").rstrip('\0')
    section_header['VirtualSize'] = int(dll_file.read(4)[::-1].hex(), 16)
    section_header['VirtualAddress'] = int(dll_file.read(4)[::-1].hex(), 16)
    section_header['SizeOfRawData'] = int(dll_file.read(4)[::-1].hex(), 16)
    section_header['PointerToRawData'] = int(dll_file.read(4)[::-1].hex(), 16)
    section_header['PointerToRelocations'] = int(dll_file.read(4)[::-1].hex(), 16)
    section_header['PointerToLineNumbers'] = int(dll_file.read(4)[::-1].hex(), 16)
    section_header['NumberOfRelocations'] = int(dll_file.read(2)[::-1].hex(), 16)
    section_header['NumberOfLineNumbers'] = int(dll_file.read(2)[::-1].hex(), 16)
    section_header['Characteristics'] = int(dll_file.read(4)[::-1].hex(), 16)
    section_headers.append(section_header)

# Getting dll information
# Dll's are located in import table
# First we need to get the section of import table
import_table_section = None
for i in section_headers:
    if i['VirtualAddress'] <= import_table and i['VirtualAddress'] + i['SizeOfRawData'] > import_table:
        import_table_section = i
        break
# Using section data calculate real address of import table
import_table_real_address = import_table - import_table_section['VirtualAddress'] + \
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
dll_file.seek(import_table_real_address, 0)
image_import_descriptors = []
while True:
    image_import_descriptor = dict()
    image_import_descriptor['Characteristics'] = int(dll_file.read(4)[::-1].hex(), 16)
    image_import_descriptor['TimeDateStamp'] = int(dll_file.read(4)[::-1].hex(), 16)
    image_import_descriptor['ForwarderChain'] = int(dll_file.read(4)[::-1].hex(), 16)
    image_import_descriptor['Name'] = int(dll_file.read(4)[::-1].hex(), 16)
    image_import_descriptor['FirstThunk'] = int(dll_file.read(4)[::-1].hex(), 16)
    if image_import_descriptor['Characteristics'] == 0:
        break
    image_import_descriptors.append(image_import_descriptor)

# Get image import descriptor names
for descriptor in image_import_descriptors:
    descriptor_name_address = descriptor['Name'] - import_table_section['VirtualAddress'] + \
        import_table_section['PointerToRawData']
    dll_file.seek(descriptor_name_address, 0)
    name = dll_file.read(100)  # I hope that 100 symbols is enough for dll name
    descriptor['RealName'] = name.decode('ANSI')[:name.decode('ANSI').find('\x00')]

# Print dll dependencies
for descriptor in image_import_descriptors:
    print(descriptor['RealName'])
