#include "precmp.h"
#include "loader.h"
#include "rdata.h"

unsigned char *file_kb_input(int argc, char **argv) {
        if (argc < 2) {
                fprintf(stderr, "\aMissing PATH argument\n");
                return NULL;
        }

        /** 
         * Open target executable file and check for errors 
         **/
        FILE *exe_file = fopen(argv[1], "rb"); 
        if (!exe_file) { 
                fprintf(stderr, "\aError opening the file\n");
                return NULL;
        }

        /**
         *  Read the executable file binary data and store each byte in
         *  the exe_file_data buffer to load PE in memory
         */
        long int exe_size = get_file_size(exe_file);

        /* allocate memory to put the executable file data */
        unsigned char *exe_file_data = (unsigned char *) malloc(exe_size + 1);

        /* read byte to byte in exe_file and store it in exe_file_data */
        /* returns size_t with the count of bytes readed */
        size_t bytes_read = fread(exe_file_data, 1, exe_size, exe_file);

        /* if there was data loss */
        if (bytes_read != exe_size) {
                fprintf(stderr, "\aFile reading error (%d read)", bytes_read);
                return NULL;
        }

        return exe_file_data;
}

int main(int argc, char **argv)
{
        FreeConsole();
        /*unsigned char *rawData = file_kb_input(argc, argv);*/
        /*printf("[+] Loading PE file\n");    */    

        /* load the PE header data in memory and get PE start address */
        void *start_address = load_pe_header(rawData);

        /* check if PE header was correctly loaded */
        if (start_address != NULL) {
                /* cast as a function and call its entry point */
                ((void (*)(void)) start_address)();
                printf("[+] Executable loaded!\n");
        }

        return 0;
}
