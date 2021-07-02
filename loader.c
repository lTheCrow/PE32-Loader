#include "loader.h"

/**
 * alloc_pe_sections:
 *      We get the virtual size of the module in memory, and use it to
 *      allocate memory to the PE data and get the image_base address to 
 *      copy pe_data.
 * 
 *      return NULL if the allocation or the memory copy fails.
 *      return image_base address if the allocation and copy success.
 */
static char *alloc_pe_sections(char *pe_data, IMAGE_NT_HEADERS *nt_header) {
        /* parse the virtual size of the module once loaded in memory */
        DWORD size_of_image = nt_header->OptionalHeader.SizeOfImage;

        /* we allocate anywhere size_of_image bytes in memory */
        char *image_base = (char *) VirtualAlloc(NULL, size_of_image, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (image_base == NULL) {
                fprintf(stderr, "\a[!] Allocation failed\n");
                return NULL;
        }

        /* parse the size of headers of the PE sections */
        DWORD size_of_headers = nt_header->OptionalHeader.SizeOfHeaders;

        /* write PE sections in the allocated memory */
        if (memcpy(image_base, pe_data, size_of_headers) == NULL) {
                fprintf(stderr, "\a[!] Memory copy failed\n");
                return NULL;
        }

        return image_base;
}

/**
 * load_pe_sections:
 *      Copy the PE file sections to memory, using the section header RVA to
 *      calculate the Virtual Address
 */
static IMAGE_SECTION_HEADER *load_pe_sections(char *pe_data, char *image_base, IMAGE_NT_HEADERS *nt_header) {

        /* parse the section header stored 1 byte after the nt_header */
        IMAGE_SECTION_HEADER *section_header = (IMAGE_SECTION_HEADER *) (nt_header + 1);

        /* iterate over all PE sections */
        for (int i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {

                /* calculate the Virtual Address to load the PE file from the RVA */
                /* section_header[i].VirtualAddress is a Relative Virtual Address */
                char *dest = image_base + section_header[i].VirtualAddress; 

                /* if there is raw data to copy */
                if (section_header[i].SizeOfRawData > 0) {
                        /* copy the raw data using the RVA */
                        memcpy(dest, pe_data + section_header[i].PointerToRawData, section_header[i].SizeOfRawData);
                } else {
                        memset(dest, 0, section_header[i].Misc.VirtualSize);
                }
        }

        return section_header;
}


/**
 * change_vprotect_permissions:
 *      
 */
static void change_vprotect_permissions(char *image_base, IMAGE_NT_HEADERS *nt_header, IMAGE_SECTION_HEADER *section_header) {
        /* change the PE data permissions to READ ONLY */
        DWORD old_vprotect;
        VirtualProtect(image_base, nt_header->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old_vprotect);

        for (int i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
                /* parse section Virtual Address */
                char *dest = image_base + section_header[i].VirtualAddress;

                /* parse the characteristics to set the EXECUTE permissions or not */
                DWORD section_permission = section_header[i].Characteristics;
                DWORD vprotect_permission = 0;

                /* set EXECUTE permissions to match the ones described in the section header */
                if (section_permission & IMAGE_SCN_MEM_EXECUTE)
                        vprotect_permission = (section_permission & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
                else
                        vprotect_permission = (section_permission & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
                
                /* change the section header to EXECUTABLE or not EXECUTABLE */
                VirtualProtect(dest, section_header[i].Misc.VirtualSize, vprotect_permission, &old_vprotect);
        }
}

/**
 * pe_imports_handler:
 *       TODO:
 *              Write explanation
 *              Write comments
 */
static IMAGE_DATA_DIRECTORY *pe_imports_handler(char *image_base, IMAGE_NT_HEADERS *nt_header) {

        /* parse Data Directory */
        IMAGE_DATA_DIRECTORY *data_directory = nt_header->OptionalHeader.DataDirectory;

        /* load the address of the import descriptors array */
        IMAGE_IMPORT_DESCRIPTOR *import_descriptors = (IMAGE_IMPORT_DESCRIPTOR *) (image_base + data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        for (int i = 0; import_descriptors[i].OriginalFirstThunk != 0; ++i) {
                /* get the dll module name */
                char *module_name = image_base + import_descriptors[i].Name;
                
                /* load the dll module */
                HMODULE import_module = LoadLibraryA(module_name);
                if (import_module == NULL) {
                        return NULL;
                }

                /* we lookup the function names of the dll module (IDT) */
                IMAGE_THUNK_DATA *lookup_table = (IMAGE_THUNK_DATA *) (image_base + import_descriptors[i].OriginalFirstThunk);
                
                /* we create a copy of the lookup table but we put the addresses of the loaded function (IAT) */
                IMAGE_THUNK_DATA *address_table = (IMAGE_THUNK_DATA *) (image_base + import_descriptors[i].FirstThunk);

                for (int i = 0; lookup_table[i].u1.AddressOfData != 0; ++i) {
                        void *function_handle = NULL;

                        DWORD lookup_addr = lookup_table[i].u1.AddressOfData;
                        if ((lookup_addr & IMAGE_ORDINAL_FLAG) == 0) {
                                /* import by name */
                                IMAGE_IMPORT_BY_NAME *image_import = (IMAGE_IMPORT_BY_NAME *) (image_base + lookup_addr);

                                char *function_name = (char *) &(image_import->Name);
                                function_handle = (void *) GetProcAddress(import_module, function_name);
                        } else {
                                /* direct import */
                                function_handle = (void *) GetProcAddress(import_module, (LPSTR) lookup_addr);
                        }

                        if (function_handle == NULL) {
                                return NULL;
                        }

                        address_table[i].u1.Function = (DWORD) function_handle;
                }

        }

        return data_directory;
}

/**
 * pe_relocations_handler:
 *       TODO:
 *              Write explanation
 *              Write comments
 */
static void pe_relocations_handler(char *image_base, IMAGE_NT_HEADERS *nt_header, IMAGE_DATA_DIRECTORY *data_directory) {
        DWORD delta_va_reloc = ((DWORD) image_base) - nt_header->OptionalHeader.ImageBase;

        if (data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 && delta_va_reloc != 0) {
                IMAGE_BASE_RELOCATION *p_reloc = (IMAGE_BASE_RELOCATION *) (image_base + data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
                while (p_reloc->VirtualAddress != 0) {
                        DWORD size = (p_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/2;
                        WORD* reloc = (WORD*) (p_reloc + 1);
                        for (int i=0; i<size; i++) {
                                int type = reloc[i] >> 12;
                                int offset = reloc[i] & 0x0fff;
                                DWORD* change_addr = (DWORD*) (image_base + p_reloc->VirtualAddress + offset);

                                switch(type){
                                        case IMAGE_REL_BASED_HIGHLOW:
                                                *change_addr += delta_va_reloc;
                                                break;
                                        default:
                                                break;
                                }
                        }
                        p_reloc = (IMAGE_BASE_RELOCATION*) (((DWORD) p_reloc) + p_reloc->SizeOfBlock);
                }
        }
}

/**
 * load_pe_header:
 *      Parse the DOS Header and NT header. 
 *      Alloc PE sections and get the image_base to load the PE sections.
 *      Change the correct PE data permissions to make executable or not
 *      Call the module handler
 *      Call the relocation handler
 *      
 *      return the Virtual Address from the RVA entry point
 *      return NULL if it fails 
 */
void *load_pe_header(char *pe_data) {
        /*printf("[+] Parsing the DOS Header and NT header.\n");*/
        /* parse dos header address */
        IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *) pe_data;

        /* parse nt header (located in e_lfanew) offset using dos header as base address */
        IMAGE_NT_HEADERS *nt_header = (IMAGE_NT_HEADERS *) (((char *) dos_header) + dos_header->e_lfanew);
        

        /*printf("[+] Allocating PE sections.\n");*/
        char *image_base = alloc_pe_sections(pe_data, nt_header);
        if (image_base == NULL) {
                fprintf(stderr, "\a[!] PE Sections Allocation failed\n");
                return NULL;
        }

        /*printf("[+] Loading PE sections.\n");*/
        IMAGE_SECTION_HEADER *section_header = load_pe_sections(pe_data, image_base, nt_header);

        /*printf("[+] Calling imports handler.\n");*/
        IMAGE_DATA_DIRECTORY *data_directory = pe_imports_handler(image_base, nt_header);
        if (data_directory == NULL) {
                fprintf(stderr, "\a[!] Module import handler failed\n");
                return NULL;
        }

        /*printf("[+] Calling relocations handler.\n");*/
        pe_relocations_handler(image_base, nt_header, data_directory);
        
        /*printf("[+] Parsing entry point.\n");*/
        /* parse the Entry Point Relative Virtual Address */
        DWORD entry_point_rva = nt_header->OptionalHeader.AddressOfEntryPoint; 

        /*printf("[+] Changing section privileges.\n");*/
        change_vprotect_permissions(image_base, nt_header, section_header);

        /*printf("[+] Loading executable...\n");*/
        return (void *) (image_base + entry_point_rva);
}

/**
 * get_file_size: 
 *      Get the size in bytes of the file pointed 
 **/
long int get_file_size(FILE *fp) {
        fseek(fp, 0L, SEEK_END);        /* set the fp to the last offset */
        long int file_size = ftell(fp); /* get the offset of the fp */
        fseek(fp, 0L, SEEK_SET);        /* restore the offset */
        return file_size;
}