/*
 * pcimem.c: Simple program to read/write from/to a pci device from userspace.
 *
 *  Copyright (C) 2010, Bill Farrow (bfarrow@beyondelectronics.us)
 *
 *  Based on the devmem2.c code
 *  Copyright (C) 2000, Jan-Derk Bakker (J.D.Bakker@its.tudelft.nl)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>
/* PCIe Config */
#include "adna.h"
#include "lib/pci.h"
/* Application */
#include "pcimem.h"
#include "eep.h"

extern char g_h1a_us_port_bar0[256];
extern struct eep_options EepOptions;

int pcimem(int access, uint32_t reg, uint32_t data)
{
    if (EepOptions.bVerbose) {
        printf("Function: %s Access: %s\n", __func__, access ? "READ" : "WRITE");
    }
	int fd = 0xFF;
	void *map_base, *virt_addr;
	uint64_t read_result, writeval, prev_read_result = 0;
	off_t target, target_base;
	int items_count = 1;
	// int verbose = 1;
	int read_result_dupped = 0;
	int type_width = 4;
	int i;
	int map_size = 4096UL;

	target = (off_t)reg;

    if ((fd = open(g_h1a_us_port_bar0, O_RDWR | O_SYNC)) == -1) PRINT_ERROR;

    fflush(stdout);

    target_base = target & ~(sysconf(_SC_PAGE_SIZE)-1);
    if (target + items_count*type_width - target_base > map_size)
	map_size = target + items_count*type_width - target_base;

    map_base = mmap(0, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target_base);
    if(map_base == (void *) -1) PRINT_ERROR;
    fflush(stdout);

    for (i = 0; i < items_count; i++) {
        virt_addr = map_base + target + i*type_width - target_base;
        read_result = *((uint32_t *) virt_addr);

        if (EepOptions.bVerbose)
            printf("Value at offset 0x%X (%p): 0x%0*lX\n", (int) target + i*type_width, virt_addr, type_width*2, read_result);
        else {
            if (read_result != prev_read_result || i == 0) {
                    if (EepOptions.bVerbose)
                        printf("0x%04X: 0x%0*lX\n", (int)(target + i*type_width), type_width*2, read_result);
                    read_result_dupped = 0;
                } else {
                    if (!read_result_dupped) {
                        if (EepOptions.bVerbose)
                            printf("...\n");
                    }
                    read_result_dupped = 1;
            }
        }
        prev_read_result = read_result;
    }
    fflush(stdout);

	if(REG_WRITE == access) {
		writeval = (uint64_t)data;
        *((uint32_t *) virt_addr) = writeval;
        read_result = *((uint32_t *) virt_addr);
        if (EepOptions.bVerbose)
		    printf("Written 0x%0*lX; readback 0x%0*lX\n", type_width*2,
		            writeval, type_width*2, read_result);
		fflush(stdout);
	}

	if(munmap(map_base, map_size) == -1) PRINT_ERROR;
    close(fd);
    return read_result;
}
