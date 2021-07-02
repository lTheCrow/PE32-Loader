#ifndef LOADER_H
#define LOADER_H

#include "precmp.h"

#include <windows.h>
#include <winnt.h>

void *load_pe_header(char *pe_data);
long int get_file_size(FILE *fp);

#endif /* LOADER_H */