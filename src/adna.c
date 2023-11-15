/** @file: adna.c
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "adna.h"
#include <stdbool.h>
#include <unistd.h>
#include <termios.h>
#include <ctype.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include "setpci.h"

#include <time.h>
#include <sys/time.h>

#define PLX_VENDOR_ID       (0x10B5)
#define PLX_H1A_DEVICE_ID   (0x8608)
#define PLX_H18_DEVICE_ID   (0x8718)

#define ASMEDIA_CLASS_ID    (0x0C03)
#define ASMEDIA_VENDOR_ID   (0x1B21)
#define ASMEDIA_DEVICE_ID   (0x2142)

#define TI_CLASS_ID         (0x0C03)
#define TI_VENDOR_ID        (0x104C)
#define TI_DEVICE_ID        (0x8241)
#define ADNATOOL_VERSION    "0.0.1"

#define H1A_DISABLE_PORT1_OFFSET    (0x0234)
#define H1A_DS_PORT1_OFFSET (0x1000)
#define LINK_OFFSET         (0x0078)
#define H1A_DS_LINK_OFFSET  ((H1A_DS_PORT1_OFFSET) + (LINK_OFFSET))

#define foreach_pci_device(acc, p) \
  for ((p) = (acc)->devices; (p) != NULL; (p) = (p)->next)

/* Options */

int verbose;              /* Show detailed information */
static int opt_hex;       /* Show contents of config space as hexadecimal numbers */
struct pci_filter filter; /* Device filter */
static int opt_path;      /* Show bridge path */
static int opt_machine;   /* Generate machine-readable output */
static int opt_domains;   /* Show domain numbers (0=disabled, 1=auto-detected, 2=requested) */
static int opt_kernel;    /* Show kernel drivers */
char *opt_pcimap;         /* Override path to Linux modules.pcimap */
static int NumDevices = 0;
const char program_name[] = "adna";
char g_h1a_us_port_bar0[256] = "\0";
uint8_t *g_pBuffer = NULL;
struct adna_options AdnaOptions;

/*** Our view of the PCI bus ***/

struct pci_access *pacc;
struct device *first_dev;
struct adna_device *first_adna = NULL;
static int seen_errors;
static int need_topology;
static bool is_initialized = false;

struct adnatool_pci_device {
        u16 vid;
        u16 did;
        u32 cls_rev;
} adnatool_pci_devtbl[] = {
        { .vid = PLX_VENDOR_ID,     .did = PLX_H1A_DEVICE_ID, .cls_rev = PCI_CLASS_BRIDGE_PCI, },
        { .vid = TI_VENDOR_ID,      .did = TI_DEVICE_ID,      .cls_rev = PCI_CLASS_SERIAL_USB, },
        {0}, /* sentinel */
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

struct adna_device {
  struct adna_device *next;
  struct pci_filter *this, *parent, *hub;
  bool bIsD3; /* Power state */
  int devnum;         /* Assigned NumDevice */
  int link_down_cnt, hub_down_cnt, link_bad_cnt; /* Error counters */
};

int pci_get_devtype(struct pci_dev *pdev);
bool pci_is_upstream(struct pci_dev *pdev);
bool pcidev_is_adnacom(struct pci_dev *p);
bool pci_dl_active(struct pci_dev *pdev);
bool pci_is_hub_alive(struct device *d);
bool pci_is_downstream(struct pci_dev *pdev);
int pci_check_link_cap(struct pci_dev *pdev);

static void stoptimer(void);
static void settimer100ms(void);
static void timer_callback(int signum);

static void pci_get_res0(struct pci_filter *f, char *path, size_t pathlen)
{
  snprintf(path, 
          pathlen,
          "/sys/bus/pci/devices/%04x:%02x:%02x.%d/resource0",
          f->domain,
          f->bus,
          f->slot,
          f->func);
  return;
}

static void pci_get_remove(struct pci_filter *f, char *path, size_t pathlen)
{
  snprintf(path, 
          pathlen,
          "/sys/bus/pci/devices/%04x:%02x:%02x.%d/remove",
          f->domain,
          f->bus,
          f->slot,
          f->func);
  return;
}

static uint32_t pcimem(int access, struct pci_filter *f, uint32_t reg, uint32_t data)
{
  int fd;
  void *map_base, *virt_addr;
  uint64_t read_result, writeval, prev_read_result = 0;
  off_t target, target_base;
  int items_count = 1;
  int read_result_dupped = 0;
  int type_width = 4;
  int i;
  int map_size = 4096UL;

  char filename[256] = "\0";
  pci_get_res0(f, filename, sizeof(filename));
  target = (off_t)reg;

  if ((fd = open(filename, O_RDWR | O_SYNC)) == -1)
    PRINT_ERROR;
  if (AdnaOptions.bVerbose) {
    printf("\n%s opened.\n", filename);
    printf("Target offset is 0x%x, page size is %ld\n", (int)target, sysconf(_SC_PAGE_SIZE));
  }
  fflush(stdout);

  target_base = target & ~(sysconf(_SC_PAGE_SIZE) - 1);
  if (target + items_count * type_width - target_base > map_size)
    map_size = target + items_count * type_width - target_base;

  /* Map one page */
  if (AdnaOptions.bVerbose)
    printf("mmap(%d, %d, 0x%x, 0x%x, %d, 0x%x)\n", 0, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (int)target);

  map_base = mmap(0, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target_base);
  if (map_base == (void *)-1)
    PRINT_ERROR;
  if (AdnaOptions.bVerbose)
    printf("PCI Memory mapped to address 0x%08lx.\n", (unsigned long)map_base);
  fflush(stdout);

  for (i = 0; i < items_count; i++) {
    virt_addr = map_base + target + i * type_width - target_base;
    read_result = *((uint32_t *)virt_addr);

    if (read_result != prev_read_result || i == 0) {
      if (AdnaOptions.bVerbose)
        printf("Reg 0x%04X: 0x%0*lX\n", (int)(target + i * type_width), type_width * 2, read_result);
      read_result_dupped = 0;
    } else {
      if (!read_result_dupped)
        printf("...\n");
      read_result_dupped = 1;
    }

    prev_read_result = read_result;
  }

  fflush(stdout);

  if (REG_WRITE == access) {
    writeval = (uint64_t)data;
    *((uint32_t *)virt_addr) = writeval;
    read_result = *((uint32_t *)virt_addr);
      
    if (AdnaOptions.bVerbose)
      printf("Written 0x%0*lX; readback 0x%0*lX\n", type_width,
            writeval, type_width, read_result);
    fflush(stdout);
  }

  if (munmap(map_base, map_size) == -1)
    PRINT_ERROR;
  close(fd);
  return (access ? 0 : (uint32_t)read_result);
}

/*! @brief Disables H1A downstream port in PCIe switch register */
static void disable_port(struct adna_device *a)
{
  int ptControl = pcimem(REG_READ, a->parent, H1A_DISABLE_PORT1_OFFSET, 0);
  ptControl |= 1;
  pcimem(REG_WRITE, a->parent, H1A_DISABLE_PORT1_OFFSET, ptControl);
}

/*! @brief Enables H1A downstream port in PCIe switch register */
static void enable_port(struct adna_device *a)
{
  int ptControl = pcimem(REG_READ, a->parent, H1A_DISABLE_PORT1_OFFSET, 0);
  ptControl &= ~1;
  pcimem(REG_WRITE, a->parent, H1A_DISABLE_PORT1_OFFSET, ptControl);
}

static char *link_compare(int sta, int cap)
{
  if (sta < cap)
    return "downgraded";
  if (sta > cap)
    return "strange";
  return "ok";
}

int pci_check_link_cap(struct pci_dev *pdev)
{
  struct pci_cap *cap;
  int status;
  uint32_t linkcap, cap_speed, cap_width, sta_speed, sta_width;
  uint16_t linksta;
  cap = pci_find_cap(pdev, PCI_CAP_ID_EXP, PCI_CAP_NORMAL);
  linkcap = pci_read_long(pdev, cap->addr + PCI_EXP_LNKCAP);
  cap_speed = linkcap & PCI_EXP_LNKCAP_SPEED;
  cap_width = (linkcap & PCI_EXP_LNKCAP_WIDTH) >> 4;
  linksta = pci_read_word(pdev, cap->addr + PCI_EXP_LNKSTA);
  sta_speed = linksta & PCI_EXP_LNKSTA_SPEED;
  sta_width = (linksta & PCI_EXP_LNKSTA_WIDTH) >> 4;

  if (    (0 == strcmp("ok", link_compare(sta_speed, cap_speed)))
       && (0 == strcmp("ok", link_compare(sta_width, cap_width)))) {
    status = IDEAL;
  } else if (    (0 != strcmp("ok", link_compare(sta_speed, cap_speed)))
              && (0 == strcmp("ok", link_compare(sta_width, cap_width)))) {
    status = SPEED_DEGRADED;
  } else if (    (0 == strcmp("ok", link_compare(sta_speed, cap_speed)))
              && (0 != strcmp("ok", link_compare(sta_width, cap_width)))) {
    status = WIDTH_DEGRADED;
  } else if (    (0 != strcmp("ok", link_compare(sta_speed, cap_speed)))
              && (0 != strcmp("ok", link_compare(sta_width, cap_width)))) {
    status = SPEED_N_WIDTH_DEGRADED;
  } else {
    ; //
  }
  return status;
}

bool pci_is_hub_alive(struct device *d)
{
  return (NULL != d->bridge->first_bus->first_dev);
}

bool pci_dl_active(struct pci_dev *pdev)
{
  struct pci_cap *cap;
  cap = pci_find_cap(pdev, PCI_CAP_ID_EXP, PCI_CAP_NORMAL);
  int linksta = pci_read_word(pdev, cap->addr + PCI_EXP_LNKSTA);
  return (linksta & PCI_EXP_LNKSTA_DL_ACT) == PCI_EXP_LNKSTA_DL_ACT;
}

int pci_get_devtype(struct pci_dev *pdev)
{
  struct pci_cap *cap;
  cap = pci_find_cap(pdev, PCI_CAP_ID_EXP, PCI_CAP_NORMAL);
  int devtype = pci_read_word(pdev, cap->addr + PCI_EXP_FLAGS);
  return ((devtype & PCI_EXP_FLAGS_TYPE) >> 4) & 0xFF;
}

bool pci_is_upstream(struct pci_dev *pdev)
{
  return pci_get_devtype(pdev) == PCI_EXP_TYPE_UPSTREAM;
}

bool pci_is_downstream(struct pci_dev *pdev)
{
  return pci_get_devtype(pdev) == PCI_EXP_TYPE_DOWNSTREAM;
}

bool pcidev_is_adnacom(struct pci_dev *p)
{
  struct adnatool_pci_device *entry;
  pci_fill_info(p, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS);
  for (entry = adnatool_pci_devtbl; entry->vid != 0; entry++) {
    if (p->vendor_id != entry->vid)
      continue;
    if (p->device_id != entry->did)
      continue;
    if (p->device_class != entry->cls_rev)
      continue;
    return true;
  }
  return false;
}

/*! @brief Removes the H1A downstream port */
static void remove_downstream(struct adna_device *a)
{
  char filename[256] = "\0";
  int dsfd, res;
  pci_get_remove(a->this, filename, sizeof(filename));
  if((dsfd = open(filename, O_WRONLY )) == -1) PRINT_ERROR;
  if((res = write( dsfd, "1", 1 )) == -1) PRINT_ERROR;
  close(dsfd);
}

/*! @brief Rescan the pci bus */
static void rescan_pci(void)
{
    int scanfd, res;
    if((scanfd = open("/sys/bus/pci/rescan", O_WRONLY )) == -1) PRINT_ERROR;
    if((res = write( scanfd, "1", 1 )) == -1) PRINT_ERROR;
    close(scanfd);
    sleep(1);
}

int config_fetch(struct device *d, unsigned int pos, unsigned int len)
{
  unsigned int end = pos+len;
  int result;

  while (pos < d->config_bufsize && len && d->present[pos])
    pos++, len--;
  while (pos+len <= d->config_bufsize && len && d->present[pos+len-1])
    len--;
  if (!len)
    return 1;

  if (end > d->config_bufsize)
    {
      int orig_size = d->config_bufsize;
      while (end > d->config_bufsize)
        d->config_bufsize *= 2;
      d->config = xrealloc(d->config, d->config_bufsize);
      d->present = xrealloc(d->present, d->config_bufsize);
      memset(d->present + orig_size, 0, d->config_bufsize - orig_size);
    }
  result = pci_read_block(d->dev, pos, d->config + pos, len);
  if (result)
    memset(d->present + pos, 1, len);
  return result;
}

struct device *scan_device(struct pci_dev *p)
{
  struct device *d;

  if (p->domain && !opt_domains)
    opt_domains = 1;
  if (!pci_filter_match(&filter, p) && !need_topology)
    return NULL;

  if (!pcidev_is_adnacom(p))
    return NULL;

  d = xmalloc(sizeof(struct device));
  memset(d, 0, sizeof(*d));
  d->dev = p;
  d->config_cached = d->config_bufsize = 256;
  d->config = xmalloc(256);
  d->present = xmalloc(256);
  memset(d->present, 1, 256);

  if (!pci_read_block(p, 0, d->config, 256)) {
    fprintf(stderr, "adna: Unable to read the standard configuration space header of device %04x:%02x:%02x.%d\n",
            p->domain, p->bus, p->dev, p->func);
    seen_errors++;
    return NULL;
  }

  pci_setup_cache(p, d->config, d->config_cached);
  pci_fill_info(p, PCI_FILL_IDENT | PCI_FILL_CLASS);
  return d;
}

static void scan_devices(void)
{
  struct device *d;
  struct pci_dev *p;

  pci_scan_bus(pacc);
  for (p=pacc->devices; p; p=p->next)
    if (d = scan_device(p)) {
      d->next = first_dev;
      first_dev = d;
    }
}

/*** Config space accesses ***/
static void check_conf_range(struct device *d, unsigned int pos, unsigned int len)
{
  while (len)
    if (!d->present[pos])
      die("Internal bug: Accessing non-read configuration byte at position %x", pos);
    else
      pos++, len--;
}

byte get_conf_byte(struct device *d, unsigned int pos)
{
  check_conf_range(d, pos, 1);
  return d->config[pos];
}

word get_conf_word(struct device *d, unsigned int pos)
{
  check_conf_range(d, pos, 2);
  return d->config[pos] | (d->config[pos+1] << 8);
}

u32 get_conf_long(struct device *d, unsigned int pos)
{
  check_conf_range(d, pos, 4);
  return d->config[pos] |
    (d->config[pos+1] << 8) |
    (d->config[pos+2] << 16) |
    (d->config[pos+3] << 24);
}

/*** Sorting ***/
static int compare_them(const void *A, const void *B)
{
  const struct pci_dev *a = (*(const struct device **)A)->dev;
  const struct pci_dev *b = (*(const struct device **)B)->dev;

  if (a->domain < b->domain)
    return -1;
  if (a->domain > b->domain)
    return 1;
  if (a->bus < b->bus)
    return -1;
  if (a->bus > b->bus)
    return 1;
  if (a->dev < b->dev)
    return -1;
  if (a->dev > b->dev)
    return 1;
  if (a->func < b->func)
    return -1;
  if (a->func > b->func)
    return 1;
  return 0;
}

static int count_downstream(void)
{
  struct device *d;
  int i=0;
  for (d=first_dev; d; d=d->next) {
    if (pci_filter_match(&filter, d->dev)) {
      if (pci_is_downstream(d->dev))
        d->NumDevice = ++i;
      else
        d->NumDevice = 0;
    }
  }

  return i;
}

static void sort_them(void)
{
  struct device **index, **h, **last_dev;
  int cnt;
  struct device *d;

  cnt = 0;
  for (d=first_dev; d; d=d->next)
    cnt++;
  h = index = alloca(sizeof(struct device *) * cnt);
  for (d=first_dev; d; d=d->next)
    *h++ = d;
  qsort(index, cnt, sizeof(struct device *), compare_them);
  last_dev = &first_dev;
  h = index;
  while (cnt--) {
    *last_dev = *h;
    last_dev = &(*h)->next;
    h++;
  }
  *last_dev = NULL;
}

/*** Normal output ***/
static void show_slot_path(struct device *d)
{
  struct pci_dev *p = d->dev;

  if (opt_path)
    {
      struct bus *bus = d->parent_bus;
      struct bridge *br = bus->parent_bridge;

      if (br && br->br_dev)
	{
	  show_slot_path(br->br_dev);
	  if (opt_path > 1)
	    printf("/%02x:%02x.%d", p->bus, p->dev, p->func);
	  else
	    printf("/%02x.%d", p->dev, p->func);
	  return;
	}
    }
  if (d->NumDevice)
    printf("[%d]\t", d->NumDevice);
  else
    printf("\t");
  printf("%02x:%02x.%d", p->bus, p->dev, p->func);
}

static void show_slot_name(struct device *d)
{
  struct pci_dev *p = d->dev;

  if (!opt_machine ? opt_domains : (p->domain || opt_domains >= 2))
    printf("%04x:", p->domain);
  show_slot_path(d);
}

void get_subid(struct device *d, word *subvp, word *subdp)
{
  byte htype = get_conf_byte(d, PCI_HEADER_TYPE) & 0x7f;

  if (htype == PCI_HEADER_TYPE_NORMAL)
    {
      *subvp = get_conf_word(d, PCI_SUBSYSTEM_VENDOR_ID);
      *subdp = get_conf_word(d, PCI_SUBSYSTEM_ID);
    }
  else if (htype == PCI_HEADER_TYPE_CARDBUS && d->config_cached >= 128)
    {
      *subvp = get_conf_word(d, PCI_CB_SUBSYSTEM_VENDOR_ID);
      *subdp = get_conf_word(d, PCI_CB_SUBSYSTEM_ID);
    }
  else
    *subvp = *subdp = 0xffff;
}

static void show_terse(struct device *d)
{
  int c;
  struct pci_dev *p = d->dev;
  char classbuf[128], devbuf[128];

  show_slot_name(d);
  printf(" %s: %s",
         pci_lookup_name(pacc, classbuf, sizeof(classbuf),
                         PCI_LOOKUP_CLASS,
                         p->device_class),
         pci_lookup_name(pacc, devbuf, sizeof(devbuf),
                         PCI_LOOKUP_VENDOR | PCI_LOOKUP_DEVICE,
                         p->vendor_id, p->device_id));
  if (c = get_conf_byte(d, PCI_REVISION_ID))
    printf(" (rev %02x)", c);
  if (verbose)
  {
    char *x;
    c = get_conf_byte(d, PCI_CLASS_PROG);
    x = pci_lookup_name(pacc, devbuf, sizeof(devbuf),
                        PCI_LOOKUP_PROGIF | PCI_LOOKUP_NO_NUMBERS,
                        p->device_class, c);
    if (c || x)
    {
      printf(" (prog-if %02x", c);
      if (x)
        printf(" [%s]", x);
      putchar(')');
    }
  }
  putchar('\n');

  if (verbose || opt_kernel)
    {
      word subsys_v, subsys_d;
#ifndef ADNA
      char ssnamebuf[256];
#endif

      pci_fill_info(p, PCI_FILL_LABEL);

      if (p->label)
        printf("\tDeviceName: %s", p->label);
      get_subid(d, &subsys_v, &subsys_d);
#ifndef ADNA
      if (subsys_v && subsys_v != 0xffff)
	printf("\tSubsystem: %s\n",
		pci_lookup_name(pacc, ssnamebuf, sizeof(ssnamebuf),
			PCI_LOOKUP_SUBSYSTEM | PCI_LOOKUP_VENDOR | PCI_LOOKUP_DEVICE,
			p->vendor_id, p->device_id, subsys_v, subsys_d));
#endif // ADNA
    }
}

/*** Verbose output ***/
static void show_size(u64 x)
{
  static const char suffix[][2] = { "", "K", "M", "G", "T" };
  unsigned i;
  if (!x)
    return;
  for (i = 0; i < (sizeof(suffix) / sizeof(*suffix) - 1); i++) {
    if (x % 1024)
      break;
    x /= 1024;
  }
  printf(" [size=%u%s]", (unsigned)x, suffix[i]);
}

static void show_bases(struct device *d, int cnt)
{
  struct pci_dev *p = d->dev;
  word cmd = get_conf_word(d, PCI_COMMAND);
  int i;
  int virtual = 0;

  for (i=0; i<cnt; i++)
    {
      pciaddr_t pos = p->base_addr[i];
      pciaddr_t len = (p->known_fields & PCI_FILL_SIZES) ? p->size[i] : 0;
      pciaddr_t ioflg = (p->known_fields & PCI_FILL_IO_FLAGS) ? p->flags[i] : 0;
      u32 flg = get_conf_long(d, PCI_BASE_ADDRESS_0 + 4*i);
      u32 hw_lower;
      u32 hw_upper = 0;
      int broken = 0;

      if (flg == 0xffffffff)
	flg = 0;
      if (!pos && !flg && !len)
	continue;

      if (verbose > 1)
	printf("\tRegion %d: ", i);
      else
	putchar('\t');

      /* Read address as seen by the hardware */
      if (flg & PCI_BASE_ADDRESS_SPACE_IO)
	hw_lower = flg & PCI_BASE_ADDRESS_IO_MASK;
      else
	{
	  hw_lower = flg & PCI_BASE_ADDRESS_MEM_MASK;
	  if ((flg & PCI_BASE_ADDRESS_MEM_TYPE_MASK) == PCI_BASE_ADDRESS_MEM_TYPE_64)
	    {
	      if (i >= cnt - 1)
		broken = 1;
	      else
		{
		  i++;
		  hw_upper = get_conf_long(d, PCI_BASE_ADDRESS_0 + 4*i);
		}
	    }
	}

      /* Detect virtual regions, which are reported by the OS, but unassigned in the device */
      if (pos && !hw_lower && !hw_upper && !(ioflg & PCI_IORESOURCE_PCI_EA_BEI))
	{
	  flg = pos;
	  virtual = 1;
	}

      /* Print base address */
      if (flg & PCI_BASE_ADDRESS_SPACE_IO)
	{
	  pciaddr_t a = pos & PCI_BASE_ADDRESS_IO_MASK;
	  printf("I/O ports at ");
	  if (a || (cmd & PCI_COMMAND_IO))
	    printf(PCIADDR_PORT_FMT, a);
	  else if (hw_lower)
	    printf("<ignored>");
	  else
	    printf("<unassigned>");
	  if (virtual)
	    printf(" [virtual]");
	  else if (!(cmd & PCI_COMMAND_IO))
	    printf(" [disabled]");
	}
      else
	{
	  int t = flg & PCI_BASE_ADDRESS_MEM_TYPE_MASK;
	  pciaddr_t a = pos & PCI_ADDR_MEM_MASK;

	  printf("Memory at ");
	  if (broken)
	    printf("<broken-64-bit-slot>");
	  else if (a)
	    printf(PCIADDR_T_FMT, a);
	  else if (hw_lower || hw_upper)
	    printf("<ignored>");
	  else
	    printf("<unassigned>");
	  printf(" (%s, %sprefetchable)",
		 (t == PCI_BASE_ADDRESS_MEM_TYPE_32) ? "32-bit" :
		 (t == PCI_BASE_ADDRESS_MEM_TYPE_64) ? "64-bit" :
		 (t == PCI_BASE_ADDRESS_MEM_TYPE_1M) ? "low-1M" : "type 3",
		 (flg & PCI_BASE_ADDRESS_MEM_PREFETCH) ? "" : "non-");
	  if (virtual)
	    printf(" [virtual]");
	  else if (!(cmd & PCI_COMMAND_MEMORY))
	    printf(" [disabled]");
	}

      if (ioflg & PCI_IORESOURCE_PCI_EA_BEI)
	printf(" [enhanced]");

      show_size(len);
      putchar('\n');
    }
}

static void show_htype0(struct device *d)
{
#ifndef ADNA
  show_bases(d, 6);
  show_rom(d, PCI_ROM_ADDRESS);
#endif // ADNA
  show_caps(d, PCI_CAPABILITY_LIST);
}

static void show_htype1(struct device *d)
{
  show_caps(d, PCI_CAPABILITY_LIST);
}

static void show_htype2(struct device *d)
{
  int i;
  word cmd = get_conf_word(d, PCI_COMMAND);
  word brc = get_conf_word(d, PCI_CB_BRIDGE_CONTROL);
  word exca;
  int verb = verbose > 2;

  show_bases(d, 1);
  printf("\tBus: primary=%02x, secondary=%02x, subordinate=%02x, sec-latency=%d\n",
	 get_conf_byte(d, PCI_CB_PRIMARY_BUS),
	 get_conf_byte(d, PCI_CB_CARD_BUS),
	 get_conf_byte(d, PCI_CB_SUBORDINATE_BUS),
	 get_conf_byte(d, PCI_CB_LATENCY_TIMER));
  for (i=0; i<2; i++)
    {
      int p = 8*i;
      u32 base = get_conf_long(d, PCI_CB_MEMORY_BASE_0 + p);
      u32 limit = get_conf_long(d, PCI_CB_MEMORY_LIMIT_0 + p);
      limit = limit + 0xfff;
      if (base <= limit || verb)
	printf("\tMemory window %d: %08x-%08x%s%s\n", i, base, limit,
	       (cmd & PCI_COMMAND_MEMORY) ? "" : " [disabled]",
	       (brc & (PCI_CB_BRIDGE_CTL_PREFETCH_MEM0 << i)) ? " (prefetchable)" : "");
    }
  for (i=0; i<2; i++)
    {
      int p = 8*i;
      u32 base = get_conf_long(d, PCI_CB_IO_BASE_0 + p);
      u32 limit = get_conf_long(d, PCI_CB_IO_LIMIT_0 + p);
      if (!(base & PCI_IO_RANGE_TYPE_32))
	{
	  base &= 0xffff;
	  limit &= 0xffff;
	}
      base &= PCI_CB_IO_RANGE_MASK;
      limit = (limit & PCI_CB_IO_RANGE_MASK) + 3;
      if (base <= limit || verb)
	printf("\tI/O window %d: %08x-%08x%s\n", i, base, limit,
	       (cmd & PCI_COMMAND_IO) ? "" : " [disabled]");
    }

  if (get_conf_word(d, PCI_CB_SEC_STATUS) & PCI_STATUS_SIG_SYSTEM_ERROR)
    printf("\tSecondary status: SERR\n");
  if (verbose > 1)
    printf("\tBridgeCtl: Parity%c SERR%c ISA%c VGA%c MAbort%c >Reset%c 16bInt%c PostWrite%c\n",
	   FLAG(brc, PCI_CB_BRIDGE_CTL_PARITY),
	   FLAG(brc, PCI_CB_BRIDGE_CTL_SERR),
	   FLAG(brc, PCI_CB_BRIDGE_CTL_ISA),
	   FLAG(brc, PCI_CB_BRIDGE_CTL_VGA),
	   FLAG(brc, PCI_CB_BRIDGE_CTL_MASTER_ABORT),
	   FLAG(brc, PCI_CB_BRIDGE_CTL_CB_RESET),
	   FLAG(brc, PCI_CB_BRIDGE_CTL_16BIT_INT),
	   FLAG(brc, PCI_CB_BRIDGE_CTL_POST_WRITES));

  if (d->config_cached < 128)
    {
      printf("\t<access denied to the rest>\n");
      return;
    }

  exca = get_conf_word(d, PCI_CB_LEGACY_MODE_BASE);
  if (exca)
    printf("\t16-bit legacy interface ports at %04x\n", exca);
  show_caps(d, PCI_CB_CAPABILITY_LIST);
}

static void show_verbose(struct device *d)
{
  struct pci_dev *p = d->dev;
  word class = p->device_class;
  byte htype = get_conf_byte(d, PCI_HEADER_TYPE) & 0x7f;
  unsigned int irq;
  byte max_lat, min_gnt;
  char *dt_node;

#ifndef ADNA
  char *iommu_group;
  byte int_pin = get_conf_byte(d, PCI_INTERRUPT_PIN);
  byte latency = get_conf_byte(d, PCI_LATENCY_TIMER);
  byte cache_line = get_conf_byte(d, PCI_CACHE_LINE_SIZE);
  byte bist = get_conf_byte(d, PCI_BIST);
  word status = get_conf_word(d, PCI_STATUS);
#else
  (void)(min_gnt);
  (void)(irq);
#endif

  show_terse(d);

  word cmd = get_conf_word(d, PCI_COMMAND);

  if ((FLAG(cmd, PCI_COMMAND_IO) == '-') ||
      (FLAG(cmd, PCI_COMMAND_MEMORY) == '-') ||
      (FLAG(cmd, PCI_COMMAND_MASTER) == '-') ) {
    byte command = (byte)(cmd | 0x7);
    pci_write_byte(d->dev, PCI_COMMAND, command);
  }

  pci_fill_info(p, PCI_FILL_IRQ | PCI_FILL_BASES | PCI_FILL_ROM_BASE | PCI_FILL_SIZES |
    PCI_FILL_PHYS_SLOT | PCI_FILL_NUMA_NODE | PCI_FILL_DT_NODE | PCI_FILL_IOMMU_GROUP);
  irq = p->irq;

  switch (htype)
  {
  case PCI_HEADER_TYPE_NORMAL:
    if (class == PCI_CLASS_BRIDGE_PCI)
      printf("\t!!! Invalid class %04x for header type %02x\n", class, htype);
    max_lat = get_conf_byte(d, PCI_MAX_LAT);
    min_gnt = get_conf_byte(d, PCI_MIN_GNT);
    break;
  case PCI_HEADER_TYPE_BRIDGE:
    if ((class >> 8) != PCI_BASE_CLASS_BRIDGE)
      printf("\t!!! Invalid class %04x for header type %02x\n", class, htype);
    min_gnt = max_lat = 0;
    break;
  case PCI_HEADER_TYPE_CARDBUS:
    if ((class >> 8) != PCI_BASE_CLASS_BRIDGE)
      printf("\t!!! Invalid class %04x for header type %02x\n", class, htype);
    min_gnt = max_lat = 0;
    break;
  default:
    printf("\t!!! Unknown header type %02x\n", htype);
    return;
  }

  if (p->phy_slot)
    printf("\tPhysical Slot: %s\n", p->phy_slot);

  if (dt_node = pci_get_string_property(p, PCI_FILL_DT_NODE))
    printf("\tDevice tree node: %s\n", dt_node);

  switch (htype)
  {
  case PCI_HEADER_TYPE_NORMAL:
    show_htype0(d);
    break;
  case PCI_HEADER_TYPE_BRIDGE:
    show_htype1(d);
    break;
  case PCI_HEADER_TYPE_CARDBUS:
    show_htype2(d);
    break;
  }
  printf("\n");
}

/*** Machine-readable dumps ***/
static void show_hex_dump(struct device *d)
{
  unsigned int i, cnt;

  cnt = d->config_cached;
  if (opt_hex >= 3 && config_fetch(d, cnt, 256-cnt))
    {
      cnt = 256;
      if (opt_hex >= 4 && config_fetch(d, 256, 4096-256))
        cnt = 4096;
    }

  for (i=0; i<cnt; i++)
    {
      if (! (i & 15))
        printf("%02x:", i);
      printf(" %02x", get_conf_byte(d, i));
      if ((i & 15) == 15)
        putchar('\n');
    }
}

static void print_shell_escaped(char *c)
{
  printf(" \"");
  while (*c)
    {
      if (*c == '"' || *c == '\\')
	putchar('\\');
      putchar(*c++);
    }
  putchar('"');
}

static void show_machine(struct device *d)
{
  struct pci_dev *p = d->dev;
  int c;
  word sv_id, sd_id;
  char classbuf[128], vendbuf[128], devbuf[128], svbuf[128], sdbuf[128];
  char *dt_node, *iommu_group;

  get_subid(d, &sv_id, &sd_id);

  if (verbose)
    {
      pci_fill_info(p, PCI_FILL_PHYS_SLOT | PCI_FILL_NUMA_NODE | PCI_FILL_DT_NODE | PCI_FILL_IOMMU_GROUP);
      printf((opt_machine >= 2) ? "Slot:\t" : "Device:\t");
      show_slot_name(d);
      putchar('\n');
      printf("Class:\t%s\n",
	     pci_lookup_name(pacc, classbuf, sizeof(classbuf), PCI_LOOKUP_CLASS, p->device_class));
      printf("Vendor:\t%s\n",
	     pci_lookup_name(pacc, vendbuf, sizeof(vendbuf), PCI_LOOKUP_VENDOR, p->vendor_id, p->device_id));
      printf("Device:\t%s\n",
	     pci_lookup_name(pacc, devbuf, sizeof(devbuf), PCI_LOOKUP_DEVICE, p->vendor_id, p->device_id));
      if (sv_id && sv_id != 0xffff)
	{
	  printf("SVendor:\t%s\n",
		 pci_lookup_name(pacc, svbuf, sizeof(svbuf), PCI_LOOKUP_SUBSYSTEM | PCI_LOOKUP_VENDOR, sv_id));
	  printf("SDevice:\t%s\n",
		 pci_lookup_name(pacc, sdbuf, sizeof(sdbuf), PCI_LOOKUP_SUBSYSTEM | PCI_LOOKUP_DEVICE, p->vendor_id, p->device_id, sv_id, sd_id));
	}
      if (p->phy_slot)
	printf("PhySlot:\t%s\n", p->phy_slot);
      if (c = get_conf_byte(d, PCI_REVISION_ID))
	printf("Rev:\t%02x\n", c);
      if (c = get_conf_byte(d, PCI_CLASS_PROG))
	printf("ProgIf:\t%02x\n", c);
      if (opt_kernel)
	show_kernel_machine(d);
      if (p->numa_node != -1)
	printf("NUMANode:\t%d\n", p->numa_node);
      if (dt_node = pci_get_string_property(p, PCI_FILL_DT_NODE))
        printf("DTNode:\t%s\n", dt_node);
      if (iommu_group = pci_get_string_property(p, PCI_FILL_IOMMU_GROUP))
	printf("IOMMUGroup:\t%s\n", iommu_group);
    }
  else
    {
      show_slot_name(d);
      print_shell_escaped(pci_lookup_name(pacc, classbuf, sizeof(classbuf), PCI_LOOKUP_CLASS, p->device_class));
      print_shell_escaped(pci_lookup_name(pacc, vendbuf, sizeof(vendbuf), PCI_LOOKUP_VENDOR, p->vendor_id, p->device_id));
      print_shell_escaped(pci_lookup_name(pacc, devbuf, sizeof(devbuf), PCI_LOOKUP_DEVICE, p->vendor_id, p->device_id));
      if (c = get_conf_byte(d, PCI_REVISION_ID))
	printf(" -r%02x", c);
      if (c = get_conf_byte(d, PCI_CLASS_PROG))
	printf(" -p%02x", c);
      if (sv_id && sv_id != 0xffff)
	{
	  print_shell_escaped(pci_lookup_name(pacc, svbuf, sizeof(svbuf), PCI_LOOKUP_SUBSYSTEM | PCI_LOOKUP_VENDOR, sv_id));
	  print_shell_escaped(pci_lookup_name(pacc, sdbuf, sizeof(sdbuf), PCI_LOOKUP_SUBSYSTEM | PCI_LOOKUP_DEVICE, p->vendor_id, p->device_id, sv_id, sd_id));
	}
      else
	printf(" \"\" \"\"");
      putchar('\n');
    }
}

/*** Main show function ***/
void show_device(struct device *d)
{
  if (opt_machine)
    show_machine(d); // not used by Adna
  else
  {
    if (verbose)
      show_verbose(d);
    else 
      show_terse(d);
#ifndef ADNA
    if (opt_kernel || verbose)
      show_kernel(d);
#endif // ADNA
  }
  if (opt_hex)
    show_hex_dump(d);
  if (verbose || opt_hex)
    putchar('\n');
}

static void show(void)
{
  struct device *d;

  for (d=first_dev; d; d=d->next)
    if (pci_filter_match(&filter, d->dev))
      if (pci_is_downstream(d->dev))
        show_verbose(d);
}

static int delete_adna_list(void)
{
  struct adna_device *a, *b;
  for (a=first_adna;a;a=b) {
    b=a->next;
    free(a->this);
    free(a->parent);
    free(a->hub);
    free(a);
  }
  return 0;
}

static int save_to_adna_list(void)
{
  struct device *d, *parent, *hub;
  struct adna_device *a;
  struct pci_filter *f, *p, *u;
  char bdf_str[17];
  char mfg_str[17];

  for (d=first_dev; d; d=d->next) {
    if (d->NumDevice) {
      a = xmalloc(sizeof(struct adna_device));
      memset(a, 0, sizeof(*a));
      a->devnum = d->NumDevice;
      f = xmalloc(sizeof(struct pci_filter));
      memset(f, 0, sizeof(*f));
      snprintf(bdf_str, sizeof(bdf_str), "%04x:%02x:%02x.%d",
               d->dev->domain, d->dev->bus, d->dev->dev, d->dev->func);
      snprintf(mfg_str, sizeof(mfg_str), "%04x:%04x:%04x",
               d->dev->vendor_id, d->dev->device_id, d->dev->device_class);
      pci_filter_parse_slot(f, bdf_str);
      pci_filter_parse_id(f, mfg_str);
      a->this = f;
      a->bIsD3 = false;
      a->link_down_cnt = 0;
      a->hub_down_cnt = 0;
      a->link_bad_cnt = 0;
      a->parent = NULL;
      a->hub = NULL;
      if (d->parent_bus->parent_bridge->br_dev != NULL) {
        parent = d->parent_bus->parent_bridge->br_dev;
        p = xmalloc(sizeof(struct pci_filter));
        snprintf(bdf_str, sizeof(bdf_str), "%04x:%02x:%02x.%d",
               parent->dev->domain, parent->dev->bus, parent->dev->dev, parent->dev->func);
        snprintf(mfg_str, sizeof(mfg_str), "%04x:%04x:%04x",
               parent->dev->vendor_id, parent->dev->device_id, parent->dev->device_class);
        pci_filter_parse_slot(p, bdf_str);
        pci_filter_parse_id(p, mfg_str);
        a->parent = p;
      }
      if (d->bridge->first_bus->first_dev != NULL) {
        u = xmalloc(sizeof(struct pci_filter));
        hub = d->bridge->first_bus->first_dev;
        snprintf(bdf_str, sizeof(bdf_str), "%04x:%02x:%02x.%d",
               hub->dev->domain, hub->dev->bus, hub->dev->dev, hub->dev->func);
        snprintf(mfg_str, sizeof(mfg_str), "%04x:%04x:%04x",
               hub->dev->vendor_id, hub->dev->device_id, hub->dev->device_class);
        pci_filter_parse_slot(u, bdf_str);
        pci_filter_parse_id(u, mfg_str);
        a->hub = u;
      }

      a->next = first_adna;
      first_adna = a;
    }
  }
  return 0;
}

static int refresh_device_cache(struct pci_dev *pdev)
{
  /* let's refresh the pcidev details */
  if (!pdev->cache) {
    u8 *cache;
    if ((cache = calloc(1, 256)) == NULL) {
      fprintf(stderr, "error allocating pci device config cache!\n");
      exit(-1);
    }
    pci_setup_cache(pdev, cache, 256);
  }

  /* refresh the config block */
  if (!pci_read_block(pdev, 0, pdev->cache, 256)) {
    fprintf(stderr, "error reading pci device config!\n");
    return -1;
  }
  return 0;
}

static int adna_pacc_cleanup(void)
{
  show_kernel_cleanup();
  pci_cleanup(pacc);
  return 0;
}

static int adna_pacc_init(void)
{
  pacc = pci_alloc();
  pacc->error = die;
  pci_filter_init(pacc, &filter);
  pci_init(pacc);
  return 0;
}

static int adna_pci_process(void)
{
  adna_pacc_init();
  scan_devices();
  sort_them();
  grow_tree();

  if (is_initialized == false) {
    NumDevices = count_downstream();
    if (NumDevices == 0) {
      printf("No Adnacom device detected.\n");
      return ENODEV;
    }
    save_to_adna_list();
    show();
    adna_pacc_cleanup();
  }

  return 0;
}

void adna_set_d3_flag(int devnum)
{
  struct adna_device *a;
  for (a = first_adna; a; a=a->next) {
    if (a->devnum == devnum)
      a->bIsD3 = true;
  }
}
#if 0
static int adna_d3_to_d0(void)
{
  struct adna_device *a;
  char *argv[4];
  int status = EXIT_SUCCESS;

  for (int i = 0; i < 4; i++) {
    argv[i] = malloc(14);
  }

  snprintf(argv[0],
           14,
           "%s",
           "setpci");

  snprintf(argv[1],
           14,
           "-s");
  snprintf(argv[3],
           14,
           "%s",
           "CAP_PM+4.b=0");

  for (a=first_adna; a; a=a->next) {
    if (a->bIsD3 == true) {
      snprintf(argv[2], 
               14,
               "%02x:%02x.%d",
               a->this->bus,
               a->this->slot,
               a->this->func);
      status = setpci(4, argv);
      if (EXIT_FAILURE == status)
        return status;
    }
  }

  for (int i = 0; i < 4; i++) {
    free(argv[i]);
  }

  return status;
}
#endif
/*! @brief 100ms timer */
static void settimer100ms(void)
{
    struct itimerval new_timer;
    struct itimerval old_timer;

    new_timer.it_value.tv_sec = 1;
    new_timer.it_value.tv_usec = 0;
    new_timer.it_interval.tv_sec = 0;
    new_timer.it_interval.tv_usec = 100 * 1000;

    setitimer(ITIMER_REAL, &new_timer, &old_timer);
    signal(SIGALRM, timer_callback);
}

/*! @brief Stop timer */
static void stoptimer(void)
{
    struct itimerval new_timer;
    struct itimerval old_timer;

    new_timer.it_value.tv_sec = 0;
    new_timer.it_value.tv_usec = 0;
    new_timer.it_interval.tv_sec = 0;
    new_timer.it_interval.tv_usec = 0;

    setitimer(ITIMER_REAL, &new_timer, &old_timer);
}

static void timer_callback(int signum)
{
  (void)(signum);
  struct adna_device *a;
  struct device *d;
  int status;
  char bdf[10];
  static bool is_linkup = false;
  static bool is_hubup = false;
  static int link_state;
  first_dev = NULL;

  status = adna_pci_process(); // Rescan all PCIe, add Adnacom device to the new lspci device list.
  if (status != EXIT_SUCCESS)
    exit(status);

  for (a = first_adna; a; a=a->next) { // This is the list of all Adnacom downstream devices (listed during init)
    snprintf(bdf, sizeof(bdf), "%02x:%02x.%d", a->this->bus, a->this->slot, a->this->func);
    if (a->bIsD3) {
      printf("%s is not Hotplug capable. Skipping device.\n", bdf);
      continue;
    }

    for (d = first_dev; d; d = d->next) {
      if (pci_filter_match(a->this, d->dev)) {
        refresh_device_cache(d->dev);
        is_linkup = pci_dl_active(d->dev);
        is_hubup = pci_is_hub_alive(d);
        printf("%s downstream port link is %s", bdf, is_linkup ? "Up" : "Down");

        if (!is_linkup) {
          a->link_down_cnt++;
        }

        if (!is_hubup) {
          a->hub_down_cnt++;
        }

        link_state = pci_check_link_cap(d->dev);
        (void)(link_state);

        if (is_linkup && !is_hubup) {
          printf(", was Down previously\n");
          stoptimer();
          rescan_pci();
          sleep(1);
          settimer100ms();
          show_verbose(d);
        } else if (!is_linkup && is_hubup) {
          printf(", was Up previously\n");
          stoptimer();
          remove_downstream(a);
          rescan_pci();
          sleep(1);
          settimer100ms();
        } else if (!is_linkup && !is_hubup) {
          if ((10 == a->link_down_cnt) || 
              (10 == a->hub_down_cnt)) {
            printf(" and has been Down for 1s\n");
            printf("%s disabling/enabling port", bdf);
            a->link_down_cnt = 0;
            a->hub_down_cnt = 0;
            disable_port(a);
            for (int noop = 0; noop < 100; noop++) { }
            enable_port(a);
          }
        } else {
          ;//
        }
        printf("\n");
      }
    }
  }
  adna_pacc_cleanup();
}

/* Main */
int main(int argc, char **argv)
{
  verbose = 2; // flag used by pci process
  int status = EXIT_SUCCESS;
  uint8_t remaining = 3; // arbitrary delay before first run

  struct itimerval new_timer;
  struct itimerval old_timer;

  new_timer.it_value.tv_sec = 1;
  new_timer.it_value.tv_usec = 0;
  new_timer.it_interval.tv_sec = 0;
  new_timer.it_interval.tv_usec = 100 * 1000;

  if (argc == 2 && !strcmp(argv[1], "--version")) {
    puts("Adnacom version " ADNATOOL_VERSION);
    return 0;
  } else if ((argc == 2 && !strcmp(argv[1], "-v"))) {
    AdnaOptions.bVerbose = true;
  }

  status = adna_pci_process();
  if (status != EXIT_SUCCESS)
    exit(1);
  else
    is_initialized = true;

  setitimer(ITIMER_REAL, &new_timer, &old_timer);
  signal(SIGALRM, timer_callback);

  while (sleep(remaining) != 0) {
    if (errno == EINTR) {
      ;// PRINTF("Timer Interrupt ");
    } else {
      printf("Sleep error %s\n", strerror(errno));
    }
  }

  status = delete_adna_list();
  if (status != EXIT_SUCCESS)
    exit(1);

  return (seen_errors ? 2 : 0);
}
