/** @file: adna.h
 *
 * Adnacom PCIe Hotplug tool
 * Copyright (C) 2022-2023, Adnacom Inc
 *
 * Based on the PCI Library
 * Copyright (c) 1998--2020 Martin Mares <mj@ucw.cz>
 * pcimem.c code
 * Copyright (C) 2010, Bill Farrow (bfarrow@beyondelectronics.us)
 * devmem2.c code
 * Copyright (C) 2000, Jan-Derk Bakker (J.D.Bakker@its.tudelft.nl)
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

#ifndef __ADNA_H__
#define __ADNA_H__

#define PCIUTILS_LSPCI
#include "pciutils.h"
#include "common.h"
#include <stdbool.h>

/*
 *  If we aren't being compiled by GCC, use xmalloc() instead of alloca().
 *  This increases our memory footprint, but only slightly since we don't
 *  use alloca() much.
 */
#if defined (__FreeBSD__) || defined (__NetBSD__) || defined (__OpenBSD__) || defined (__DragonFly__) || defined (__DJGPP__)
/* alloca() is defined in stdlib.h */
#elif defined(__GNUC__) && !defined(PCI_OS_WINDOWS)
#include <alloca.h>
#else
#undef alloca
#define alloca xmalloc
#endif

#define PRINT_ERROR \
    do { \
        fprintf(stderr, "Error at line %d, file %s (%d) [%s]\n", \
        __LINE__, __FILE__, errno, strerror(errno)); exit(1); \
    } while(0)

/*** Options ***/

extern int verbose;
extern struct pci_filter filter;
extern char *opt_pcimap;
extern struct device *first_dev;
extern struct pci_access *pacc;

struct device *scan_device(struct pci_dev *p);
void show_device(struct device *d);
int config_fetch(struct device *d, unsigned int pos, unsigned int len);
u32 get_conf_long(struct device *d, unsigned int pos);
word get_conf_word(struct device *d, unsigned int pos);
byte get_conf_byte(struct device *d, unsigned int pos);
void get_subid(struct device *d, word *subvp, word *subdp);

/* Useful macros for decoding of bits and bit fields */

#define FLAG(x,y) ((x & y) ? '+' : '-')
#define BITS(x,at,width) (((x) >> (at)) & ((1 << (width)) - 1))
#define TABLE(tab,x,buf) ((x) < sizeof(tab)/sizeof((tab)[0]) ? (tab)[x] : (sprintf((buf), "??%d", (x)), (buf)))

#define ADNA // Selective adna print out

// PCI device Power Management states (PM Cntrl/Stat [1:0])
#define PCI_CAP_PM_STATE_D0                     0x00
#define PCI_CAP_PM_STATE_D1                     0x01
#define PCI_CAP_PM_STATE_D2                     0x02
#define PCI_CAP_PM_STATE_D3_HOT                 0x03

struct device {
  struct device *next;
  struct pci_dev *dev;
  /* Bus topology calculated by grow_tree() */
  struct device *bus_next;
  struct bus *parent_bus;
  struct bridge *bridge;
  /* Cache */
  unsigned int config_cached, config_bufsize;
  byte *config;				/* Cached configuration space data */
  byte *present;			/* Maps which configuration bytes are present */
  int NumDevice;
};

/*** PCI devices and access to their config space ***/
struct bridge {
  struct bridge *chain;			/* Single-linked list of bridges */
  struct bridge *next, *child;		/* Tree of bridges */
  struct bus *first_bus;		/* List of buses connected to this bridge */
  unsigned int domain;
  unsigned int primary, secondary, subordinate;	/* Bus numbers */
  struct device *br_dev;
};

struct bus {
  unsigned int domain;
  unsigned int number;
  struct bus *sibling;
  struct bridge *parent_bridge;
  struct device *first_dev, **last_dev;
};

enum link_state {
  IDEAL,
  SPEED_DEGRADED,
  WIDTH_DEGRADED,
  SPEED_N_WIDTH_DEGRADED,
  LINK_QUALITY_MAX
};

enum access {
    REG_READ,
    REG_WRITE
};

struct adna_options {
  bool bVerbose;
  int bLoadFile;
  char    FileName[255];
  char    SerialNumber[4];
  u16     ExtraBytes;
  bool bListOnly;
  bool bSerialNumber;
};

/* ls-vpd.c */

void cap_vpd(struct device *d);

/* ls-ecaps.c */

void show_ext_caps(struct device *d, int type);

/* ls-caps-vendor.c */

void show_vendor_caps(struct device *d, int where, int cap);

/* ls-kernel.c */

void show_kernel_machine(struct device *d UNUSED);
void show_kernel(struct device *d UNUSED);
void show_kernel_cleanup(void);

/* ls-tree.c */

extern struct bridge host_bridge;

void grow_tree(void);
void show_forest(struct pci_filter *filter);

/* ls-map.c */

void map_the_bus(void);
void adna_set_d3_flag(int devnum);

int adna_pci_process(void);
void adna_set_init_flag(bool value);
void adna_timer_callback(int signum);
int adna_delete_list(void);
int adna_get_errors(void);

#endif //__ADNA_H__