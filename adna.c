/*
 *	The PCI Utilities -- List All PCI Devices
 *
 *	Copyright (c) 1997--2020 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "adna.h"
#include "pcimem.h"
#include <stdbool.h>
#include "eep.h"
#include <unistd.h>
#include <termios.h>

#define PLX_VENDOR_ID       (0x10B5)
#define PLX_H1A_DEVICE_ID   (0x8608)
#define ADNATOOL_VERSION    "0.0.1"

/* Options */

int verbose;				/* Show detailed information */
static int opt_hex;			/* Show contents of config space as hexadecimal numbers */
struct pci_filter filter;		/* Device filter */
static int opt_path;			/* Show bridge path */
static int opt_machine;			/* Generate machine-readable output */
static int opt_domains;			/* Show domain numbers (0=disabled, 1=auto-detected, 2=requested) */
static int opt_kernel;			/* Show kernel drivers */
#ifndef ADNA
static int opt_filter;			/* Any filter was given */
static int opt_tree;			/* Show bus tree */
static int opt_map_mode;		/* Bus mapping mode enabled */
static int opt_query_dns;		/* Query the DNS (0=disabled, 1=enabled, 2=refresh cache) */
static int opt_query_all;		/* Query the DNS for all entries */
#endif // ADNA
char *opt_pcimap;			/* Override path to Linux modules.pcimap */

const char program_name[] = "adna";
#ifndef ADNA
static char options[] = "nvbxs:d:tPi:mgp:qkMDQ" GENERIC_OPTIONS ;

static char help_msg[] =
"Usage: adna [<switches>]\n"
"\n"
"Basic display modes:\n"
"-mm\t\tProduce machine-readable output (single -m for an obsolete format)\n"
"-t\t\tShow bus tree\n"
"\n"
"Display options:\n"
"-v\t\tBe verbose (-vv or -vvv for higher verbosity)\n"
#ifdef PCI_OS_LINUX
"-k\t\tShow kernel drivers handling each device\n"
#endif
"-x\t\tShow hex-dump of the standard part of the config space\n"
"-xxx\t\tShow hex-dump of the whole config space (dangerous; root only)\n"
"-xxxx\t\tShow hex-dump of the 4096-byte extended config space (root only)\n"
"-b\t\tBus-centric view (addresses and IRQ's as seen by the bus)\n"
"-D\t\tAlways show domain numbers\n"
"-P\t\tDisplay bridge path in addition to bus and device number\n"
"-PP\t\tDisplay bus path in addition to bus and device number\n"
"\n"
"Resolving of device ID's to names:\n"
"-n\t\tShow numeric ID's\n"
"-nn\t\tShow both textual and numeric ID's (names & numbers)\n"
#ifdef PCI_USE_DNS
"-q\t\tQuery the PCI ID database for unknown ID's via DNS\n"
"-qq\t\tAs above, but re-query locally cached entries\n"
"-Q\t\tQuery the PCI ID database for all ID's via DNS\n"
#endif
"\n"
"Selection of devices:\n"
"-s [[[[<domain>]:]<bus>]:][<slot>][.[<func>]]\tShow only devices in selected slots\n"
"-d [<vendor>]:[<device>][:<class>]\t\tShow only devices with specified ID's\n"
"\n"
"Other options:\n"
"-i <file>\tUse specified ID database instead of %s\n"
#ifdef PCI_OS_LINUX
"-p <file>\tLook up kernel modules in a given file instead of default modules.pcimap\n"
#endif
"-M\t\tEnable `bus mapping' mode (dangerous; root only)\n"
"\n"
"PCI access options:\n"
GENERIC_HELP
;
#endif // ADNA
char g_h1a_us_port_bar0[256] = "\0";

struct eep_options EepOptions;

/*** Our view of the PCI bus ***/

struct pci_access *pacc;
struct device *first_dev;
static int seen_errors;
static int need_topology;

struct adnatool_pci_device {
        u16 vid;
        u16 did;
        u32 cls_rev;
} adnatool_pci_devtbl[] = {
#if 0
        { .vid = PLX_VENDOR_ID,     .did = PLX_H1A_DEVICE_ID, .cls_rev = PCI_CLASS_BRIDGE_PCI, },
#else
        /* for debugging purpose, put in some actual PCI devices i have 
         * in my system. TODO: remove these! */
        { .vid = 0x8086, .did = 0x02b0, .cls_rev = PCI_CLASS_BRIDGE_PCI, },
        { .vid = 0x10ec, .did = 0xc82f, .cls_rev = PCI_CLASS_NETWORK_OTHER, },
#endif
        {0}, /* sentinel */

};

int pci_get_devtype(struct pci_dev *pdev);
bool pci_is_upstream(struct pci_dev *pdev);
bool pcidev_is_adnacom(struct pci_dev *p);

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

bool pcidev_is_adnacom(struct pci_dev *p)
{
        struct adnatool_pci_device *entry;
        pci_fill_info(p, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS);
        // printf("vendor: 0x%02x device: 0x%02x\n", p->vendor_id, p->device_id);
        for (entry = adnatool_pci_devtbl; entry->vid != 0; entry++) {
                // printf("entry: 0x%02x device: 0x%02x\n", entry->vid, entry->did);
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

int
config_fetch(struct device *d, unsigned int pos, unsigned int len)
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

struct device *
scan_device(struct pci_dev *p)
{
  struct device *d;

  if (p->domain && !opt_domains)
    opt_domains = 1;
  if (!pci_filter_match(&filter, p) && !need_topology)
    return NULL;

  if (!pcidev_is_adnacom(p))
    return NULL;

//   if (!pci_is_upstream(p))
//     return NULL;

  d = xmalloc(sizeof(struct device));
  memset(d, 0, sizeof(*d));
  d->dev = p;
  d->config_cached = d->config_bufsize = 64;
  d->config = xmalloc(64);
  d->present = xmalloc(64);
  memset(d->present, 1, 64);
  if (!pci_read_block(p, 0, d->config, 64))
    {
      fprintf(stderr, "adna: Unable to read the standard configuration space header of device %04x:%02x:%02x.%d\n",
	      p->domain, p->bus, p->dev, p->func);
      seen_errors++;
      return NULL;
    }
  if ((d->config[PCI_HEADER_TYPE] & 0x7f) == PCI_HEADER_TYPE_CARDBUS)
    {
      /* For cardbus bridges, we need to fetch 64 bytes more to get the
       * full standard header... */
      if (config_fetch(d, 64, 64))
	d->config_cached += 64;
    }
  pci_setup_cache(p, d->config, d->config_cached);
  pci_fill_info(p, PCI_FILL_IDENT | PCI_FILL_CLASS);
  return d;
}

static void
scan_devices(void)
{
  struct device *d;
  struct pci_dev *p;

  pci_scan_bus(pacc);
  for (p=pacc->devices; p; p=p->next)
    if (d = scan_device(p))
      {
	d->next = first_dev;
	first_dev = d;
      }
}

/*** Config space accesses ***/

static void
check_conf_range(struct device *d, unsigned int pos, unsigned int len)
{
  while (len)
    if (!d->present[pos])
      die("Internal bug: Accessing non-read configuration byte at position %x", pos);
    else
      pos++, len--;
}

byte
get_conf_byte(struct device *d, unsigned int pos)
{
  check_conf_range(d, pos, 1);
  return d->config[pos];
}

word
get_conf_word(struct device *d, unsigned int pos)
{
  check_conf_range(d, pos, 2);
  return d->config[pos] | (d->config[pos+1] << 8);
}

u32
get_conf_long(struct device *d, unsigned int pos)
{
  check_conf_range(d, pos, 4);
  return d->config[pos] |
    (d->config[pos+1] << 8) |
    (d->config[pos+2] << 16) |
    (d->config[pos+3] << 24);
}

/*** Sorting ***/

static int
compare_them(const void *A, const void *B)
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

static void
sort_them(int *NumDevices)
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
  while (cnt--)
    {
      *last_dev = *h;
      last_dev = &(*h)->next;
      h++;
    }
  *last_dev = NULL;
  int i=1;
  for (d=first_dev; d; d=d->next) {
      if (pci_is_upstream(d->dev))
        d->NumDevice = i++;
      else
        d->NumDevice = 0;
  }
  *NumDevices = i;
}

/*** Normal output ***/

static void
show_slot_path(struct device *d)
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
    printf("[%d] ", d->NumDevice);
  else
    printf("     ");
  printf("%02x:%02x.%d", p->bus, p->dev, p->func);
}

static void
show_slot_name(struct device *d)
{
  struct pci_dev *p = d->dev;

  if (!opt_machine ? opt_domains : (p->domain || opt_domains >= 2))
    printf("%04x:", p->domain);
  show_slot_path(d);
}

void
get_subid(struct device *d, word *subvp, word *subdp)
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

static void
show_terse(struct device *d)
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

static void
show_size(u64 x)
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
#ifndef ADNA
static void
show_range(char *prefix, u64 base, u64 limit, int is_64bit)
{
  printf("%s:", prefix);
  if (base <= limit || verbose > 2)
    {
      if (is_64bit)
        printf(" %016" PCI_U64_FMT_X "-%016" PCI_U64_FMT_X, base, limit);
      else
        printf(" %08x-%08x", (unsigned) base, (unsigned) limit);
    }
  if (base <= limit)
    show_size(limit - base + 1);
  else
    printf(" [disabled]");
  putchar('\n');
}
#endif
static void
show_bases(struct device *d, int cnt)
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
#ifndef ADNA
static void
show_rom(struct device *d, int reg)
{
  struct pci_dev *p = d->dev;
  pciaddr_t rom = p->rom_base_addr;
  pciaddr_t len = (p->known_fields & PCI_FILL_SIZES) ? p->rom_size : 0;
  pciaddr_t ioflg = (p->known_fields & PCI_FILL_IO_FLAGS) ? p->rom_flags : 0;
  u32 flg = get_conf_long(d, reg);
  word cmd = get_conf_word(d, PCI_COMMAND);
  int virtual = 0;

  if (!rom && !flg && !len)
    return;

  if ((rom & PCI_ROM_ADDRESS_MASK) && !(flg & PCI_ROM_ADDRESS_MASK) && !(ioflg & PCI_IORESOURCE_PCI_EA_BEI))
    {
      flg = rom;
      virtual = 1;
    }

  printf("\tExpansion ROM at ");
  if (rom & PCI_ROM_ADDRESS_MASK)
    printf(PCIADDR_T_FMT, rom & PCI_ROM_ADDRESS_MASK);
  else if (flg & PCI_ROM_ADDRESS_MASK)
    printf("<ignored>");
  else
    printf("<unassigned>");

  if (virtual)
    printf(" [virtual]");

  if (!(flg & PCI_ROM_ADDRESS_ENABLE))
    printf(" [disabled]");
  else if (!virtual && !(cmd & PCI_COMMAND_MEMORY))
    printf(" [disabled by cmd]");

  if (ioflg & PCI_IORESOURCE_PCI_EA_BEI)
      printf(" [enhanced]");

  show_size(len);
  putchar('\n');
}
#endif // ADNA
static void
show_htype0(struct device *d)
{
#ifndef ADNA
  show_bases(d, 6);
  show_rom(d, PCI_ROM_ADDRESS);
#endif // ADNA
  show_caps(d, PCI_CAPABILITY_LIST);
}

static void
show_htype1(struct device *d)
{
#ifndef ADNA
  u32 io_base = get_conf_byte(d, PCI_IO_BASE);
  u32 io_limit = get_conf_byte(d, PCI_IO_LIMIT);
  u32 io_type = io_base & PCI_IO_RANGE_TYPE_MASK;
  u32 mem_base = get_conf_word(d, PCI_MEMORY_BASE);
  u32 mem_limit = get_conf_word(d, PCI_MEMORY_LIMIT);
  u32 mem_type = mem_base & PCI_MEMORY_RANGE_TYPE_MASK;
  u32 pref_base = get_conf_word(d, PCI_PREF_MEMORY_BASE);
  u32 pref_limit = get_conf_word(d, PCI_PREF_MEMORY_LIMIT);
  u32 pref_type = pref_base & PCI_PREF_RANGE_TYPE_MASK;
  word sec_stat = get_conf_word(d, PCI_SEC_STATUS);
  word brc = get_conf_word(d, PCI_BRIDGE_CONTROL);

  show_bases(d, 2);
  printf("\tBus: primary=%02x, secondary=%02x, subordinate=%02x, sec-latency=%d\n",
	 get_conf_byte(d, PCI_PRIMARY_BUS),
	 get_conf_byte(d, PCI_SECONDARY_BUS),
	 get_conf_byte(d, PCI_SUBORDINATE_BUS),
	 get_conf_byte(d, PCI_SEC_LATENCY_TIMER));

  if (io_type != (io_limit & PCI_IO_RANGE_TYPE_MASK) ||
      (io_type != PCI_IO_RANGE_TYPE_16 && io_type != PCI_IO_RANGE_TYPE_32))
    printf("\t!!! Unknown I/O range types %x/%x\n", io_base, io_limit);
  else
    {
      io_base = (io_base & PCI_IO_RANGE_MASK) << 8;
      io_limit = (io_limit & PCI_IO_RANGE_MASK) << 8;
      if (io_type == PCI_IO_RANGE_TYPE_32)
	{
	  io_base |= (get_conf_word(d, PCI_IO_BASE_UPPER16) << 16);
	  io_limit |= (get_conf_word(d, PCI_IO_LIMIT_UPPER16) << 16);
	}
      show_range("\tI/O behind bridge", io_base, io_limit+0xfff, 0);
    }

  if (mem_type != (mem_limit & PCI_MEMORY_RANGE_TYPE_MASK) ||
      mem_type)
    printf("\t!!! Unknown memory range types %x/%x\n", mem_base, mem_limit);
  else
    {
      mem_base = (mem_base & PCI_MEMORY_RANGE_MASK) << 16;
      mem_limit = (mem_limit & PCI_MEMORY_RANGE_MASK) << 16;
      show_range("\tMemory behind bridge", mem_base, mem_limit + 0xfffff, 0);
    }

  if (pref_type != (pref_limit & PCI_PREF_RANGE_TYPE_MASK) ||
      (pref_type != PCI_PREF_RANGE_TYPE_32 && pref_type != PCI_PREF_RANGE_TYPE_64))
    printf("\t!!! Unknown prefetchable memory range types %x/%x\n", pref_base, pref_limit);
  else
    {
      u64 pref_base_64 = (pref_base & PCI_PREF_RANGE_MASK) << 16;
      u64 pref_limit_64 = (pref_limit & PCI_PREF_RANGE_MASK) << 16;
      if (pref_type == PCI_PREF_RANGE_TYPE_64)
	{
	  pref_base_64 |= (u64) get_conf_long(d, PCI_PREF_BASE_UPPER32) << 32;
	  pref_limit_64 |= (u64) get_conf_long(d, PCI_PREF_LIMIT_UPPER32) << 32;
	}
      show_range("\tPrefetchable memory behind bridge", pref_base_64, pref_limit_64 + 0xfffff, (pref_type == PCI_PREF_RANGE_TYPE_64));
    }

  if (verbose > 1)
    printf("\tSecondary status: 66MHz%c FastB2B%c ParErr%c DEVSEL=%s >TAbort%c <TAbort%c <MAbort%c <SERR%c <PERR%c\n",
	     FLAG(sec_stat, PCI_STATUS_66MHZ),
	     FLAG(sec_stat, PCI_STATUS_FAST_BACK),
	     FLAG(sec_stat, PCI_STATUS_PARITY),
	     ((sec_stat & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_SLOW) ? "slow" :
	     ((sec_stat & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_MEDIUM) ? "medium" :
	     ((sec_stat & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_FAST) ? "fast" : "??",
	     FLAG(sec_stat, PCI_STATUS_SIG_TARGET_ABORT),
	     FLAG(sec_stat, PCI_STATUS_REC_TARGET_ABORT),
	     FLAG(sec_stat, PCI_STATUS_REC_MASTER_ABORT),
	     FLAG(sec_stat, PCI_STATUS_SIG_SYSTEM_ERROR),
	     FLAG(sec_stat, PCI_STATUS_DETECTED_PARITY));

  show_rom(d, PCI_ROM_ADDRESS1);

  if (verbose > 1)
    {
      printf("\tBridgeCtl: Parity%c SERR%c NoISA%c VGA%c VGA16%c MAbort%c >Reset%c FastB2B%c\n",
	FLAG(brc, PCI_BRIDGE_CTL_PARITY),
	FLAG(brc, PCI_BRIDGE_CTL_SERR),
	FLAG(brc, PCI_BRIDGE_CTL_NO_ISA),
	FLAG(brc, PCI_BRIDGE_CTL_VGA),
	FLAG(brc, PCI_BRIDGE_CTL_VGA_16BIT),
	FLAG(brc, PCI_BRIDGE_CTL_MASTER_ABORT),
	FLAG(brc, PCI_BRIDGE_CTL_BUS_RESET),
	FLAG(brc, PCI_BRIDGE_CTL_FAST_BACK));
      printf("\t\tPriDiscTmr%c SecDiscTmr%c DiscTmrStat%c DiscTmrSERREn%c\n",
	FLAG(brc, PCI_BRIDGE_CTL_PRI_DISCARD_TIMER),
	FLAG(brc, PCI_BRIDGE_CTL_SEC_DISCARD_TIMER),
	FLAG(brc, PCI_BRIDGE_CTL_DISCARD_TIMER_STATUS),
	FLAG(brc, PCI_BRIDGE_CTL_DISCARD_TIMER_SERR_EN));
    }
#endif // ADNA
  show_caps(d, PCI_CAPABILITY_LIST);
}

static void
show_htype2(struct device *d)
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

static void
show_verbose(struct device *d)
{
  struct pci_dev *p = d->dev;
  word class = p->device_class;
  byte htype = get_conf_byte(d, PCI_HEADER_TYPE) & 0x7f;
  unsigned int irq;
  byte max_lat, min_gnt;
  char *dt_node;

#ifndef ADNA
  char *iommu_group;
  word cmd = get_conf_word(d, PCI_COMMAND);
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
#ifndef ADNA
  if (verbose > 1)
    {
      printf("\tControl: I/O%c Mem%c BusMaster%c SpecCycle%c MemWINV%c VGASnoop%c ParErr%c Stepping%c SERR%c FastB2B%c DisINTx%c\n",
	     FLAG(cmd, PCI_COMMAND_IO),
	     FLAG(cmd, PCI_COMMAND_MEMORY),
	     FLAG(cmd, PCI_COMMAND_MASTER),
	     FLAG(cmd, PCI_COMMAND_SPECIAL),
	     FLAG(cmd, PCI_COMMAND_INVALIDATE),
	     FLAG(cmd, PCI_COMMAND_VGA_PALETTE),
	     FLAG(cmd, PCI_COMMAND_PARITY),
	     FLAG(cmd, PCI_COMMAND_WAIT),
	     FLAG(cmd, PCI_COMMAND_SERR),
	     FLAG(cmd, PCI_COMMAND_FAST_BACK),
	     FLAG(cmd, PCI_COMMAND_DISABLE_INTx));
      printf("\tStatus: Cap%c 66MHz%c UDF%c FastB2B%c ParErr%c DEVSEL=%s >TAbort%c <TAbort%c <MAbort%c >SERR%c <PERR%c INTx%c\n",
	     FLAG(status, PCI_STATUS_CAP_LIST),
	     FLAG(status, PCI_STATUS_66MHZ),
	     FLAG(status, PCI_STATUS_UDF),
	     FLAG(status, PCI_STATUS_FAST_BACK),
	     FLAG(status, PCI_STATUS_PARITY),
	     ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_SLOW) ? "slow" :
	     ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_MEDIUM) ? "medium" :
	     ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_FAST) ? "fast" : "??",
	     FLAG(status, PCI_STATUS_SIG_TARGET_ABORT),
	     FLAG(status, PCI_STATUS_REC_TARGET_ABORT),
	     FLAG(status, PCI_STATUS_REC_MASTER_ABORT),
	     FLAG(status, PCI_STATUS_SIG_SYSTEM_ERROR),
	     FLAG(status, PCI_STATUS_DETECTED_PARITY),
	     FLAG(status, PCI_STATUS_INTx));
      if (cmd & PCI_COMMAND_MASTER)
	{
	  printf("\tLatency: %d", latency);
	  if (min_gnt || max_lat)
	    {
	      printf(" (");
	      if (min_gnt)
		printf("%dns min", min_gnt*250);
	      if (min_gnt && max_lat)
		printf(", ");
	      if (max_lat)
		printf("%dns max", max_lat*250);
	      putchar(')');
	    }
	  if (cache_line)
	    printf(", Cache Line Size: %d bytes", cache_line * 4);
	  putchar('\n');
	}
      if (int_pin || irq)
	printf("\tInterrupt: pin %c routed to IRQ " PCIIRQ_FMT "\n",
	       (int_pin ? 'A' + int_pin - 1 : '?'), irq);
      if (p->numa_node != -1)
	printf("\tNUMA node: %d\n", p->numa_node);
      if (iommu_group = pci_get_string_property(p, PCI_FILL_IOMMU_GROUP))
	printf("\tIOMMU group: %s\n", iommu_group);
    }
  else
    {
      printf("\tFlags: ");
      if (cmd & PCI_COMMAND_MASTER)
	printf("bus master, ");
      if (cmd & PCI_COMMAND_VGA_PALETTE)
	printf("VGA palette snoop, ");
      if (cmd & PCI_COMMAND_WAIT)
	printf("stepping, ");
      if (cmd & PCI_COMMAND_FAST_BACK)
	printf("fast Back2Back, ");
      if (status & PCI_STATUS_66MHZ)
	printf("66MHz, ");
      if (status & PCI_STATUS_UDF)
	printf("user-definable features, ");
      printf("%s devsel",
	     ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_SLOW) ? "slow" :
	     ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_MEDIUM) ? "medium" :
	     ((status & PCI_STATUS_DEVSEL_MASK) == PCI_STATUS_DEVSEL_FAST) ? "fast" : "??");
      if (cmd & PCI_COMMAND_MASTER)
	printf(", latency %d", latency);
      if (irq)
	printf(", IRQ " PCIIRQ_FMT, irq);
      if (p->numa_node != -1)
	printf(", NUMA node %d", p->numa_node);
      if (iommu_group = pci_get_string_property(p, PCI_FILL_IOMMU_GROUP))
	printf(", IOMMU group %s", iommu_group);
      putchar('\n');
    }

  if (bist & PCI_BIST_CAPABLE)
    {
      if (bist & PCI_BIST_START)
	printf("\tBIST is running\n");
      else
	printf("\tBIST result: %02x\n", bist & PCI_BIST_CODE_MASK);
    }
#endif // ADNA
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
}

/*** Machine-readable dumps ***/

static void
show_hex_dump(struct device *d)
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

static void
print_shell_escaped(char *c)
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

static void
show_machine(struct device *d)
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

void
show_device(struct device *d)
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

static void
show(void)
{
  struct device *d;

  for (d=first_dev; d; d=d->next)
    if (pci_filter_match(&filter, d->dev))
      show_device(d);
}

static uint8_t EepromFileLoad(void)
{
    printf("Function: %s\n", __func__);
    uint8_t rc;
    uint8_t *pBuffer;
    uint8_t four_byte_count;
    uint16_t Verify_Value_16 = 0;
    uint32_t value;
    uint32_t Verify_Value = 0;
    uint32_t offset;
    uint32_t FileSize;
    FILE *pFile;

    pBuffer   = NULL;

    printf("Load EEPROM file... \n");
    fflush(stdout);

    // Open the file to read
    pFile = fopen(EepOptions.FileName, "rb");
    if (pFile == NULL) {
        printf("ERROR: Unable to load \"%s\"\n", EepOptions.FileName);
        return EEP_FAIL;
    }

    // Move to end-of-file
    fseek(pFile, 0, SEEK_END);

    // Determine file size
    FileSize = ftell(pFile);

    // Move back to start of file
    fseek(pFile, 0, SEEK_SET);

    // Allocate a buffer for the data
    pBuffer = malloc(FileSize);
    if (pBuffer == NULL) {
        fclose(pFile);
        return EEP_FAIL;
    }

    // Read data from file
    if (fread(
            pBuffer,        // Buffer for data
            sizeof(uint8_t),// Item size
            FileSize,       // Buffer size
            pFile           // File pointer
            ) <= 0) {
        // Added for compiler warning
    }

    // Close the file
    fclose(pFile);

    printf("Ok (%dB)\n", (int)FileSize);

    // Default to successful operation
    rc = EXIT_SUCCESS;

    printf("Program EEPROM..... \n");

    // Write 32-bit aligned buffer into EEPROM
    for (offset = 0, four_byte_count = 0; offset < (FileSize & ~0x3); four_byte_count++, offset += sizeof(uint32_t))
    {
        // Periodically update status
        if ((offset & 0x7) == 0) {
            // Display current status
            printf("%02u%%\b\b\b", ((offset * 100) / FileSize));
            fflush( stdout );
        }

        // Get next value
        value = *(uint32_t*)(pBuffer + offset);

        // Write value & read back to verify
        eep_write(four_byte_count, value);
        eep_read(four_byte_count, &Verify_Value);

        if (Verify_Value != value) {
            printf("ERROR: offset:%02X  wrote:%08X  read:%08X\n",
                   offset, value, Verify_Value);
            rc = EEP_FAIL;
            goto _Exit_File_Load;
        }
    }

    // Write any remaining 16-bit unaligned value
    if (offset < FileSize) {
        // Get next value
        value = *(uint16_t*)(pBuffer + offset);

        // Write value & read back to verify
        eep_write_16(offset, (uint16_t)value);
        eep_read_16(offset, &Verify_Value_16);

        if (Verify_Value_16 != (uint16_t)value) {
            printf("ERROR: offset:%02X  wrote:%04X  read:%04X\n",
                   offset, value, Verify_Value_16);
            goto _Exit_File_Load;
        }
    }
    printf("Ok \n");

_Exit_File_Load:
    // Release the buffer
    if (pBuffer != NULL) {
        free(pBuffer);
    }

    return rc;
}

static uint8_t EepromFileSave(void)
{
    printf("Function: %s\n", __func__);
    uint8_t *pBuffer;
    uint32_t value = 0;
    uint32_t offset;
    uint8_t four_byte_count;
    uint32_t EepSize;
    FILE *pFile;

    printf("Get EEPROM data size.. \n");

    pBuffer = NULL;

    // Start with EEPROM header size
    EepSize = sizeof(uint32_t);

    // Get EEPROM header
    eep_read(0x0, &value);

    // Add register byte count
    EepSize += (value >> 16);

    printf("Ok (%d Bytes", EepSize);

    /* ExtraBytes may not be needed */
    if (EepOptions.ExtraBytes) {
        printf(" + %dB extra", EepOptions.ExtraBytes);

        // Adjust for extra bytes
        EepSize += EepOptions.ExtraBytes;

        // Make sure size aligned on 16-bit boundary
        EepSize = (EepSize + 1) & ~(uint32_t)0x1;
    }
    printf(")\n");

    printf("Read EEPROM data...... \n");
    fflush(stdout);

    // Allocate a buffer for the EEPROM data
    pBuffer = malloc(EepSize);
    if (pBuffer == NULL) {
        return EEP_FAIL;
    }

    // Each EEPROM read via BAR0 is 4 bytes so offset is represented in bytes (aligned in 32 bits)
    // while four_byte_count is represented in count of 4-byte access
    for (offset = 0, four_byte_count = 0; offset < (EepSize & ~0x3); offset += sizeof(uint32_t), four_byte_count++) {
        eep_read(four_byte_count, (uint32_t*)(pBuffer + offset));
    }

    // Read any remaining 16-bit aligned byte
    if (offset < EepSize) {
        eep_read_16(four_byte_count, (uint16_t*)(pBuffer + offset));
    }
    printf("Ok\n");

    printf("Write data to file.... \n");
    fflush(stdout);

    // Open the file to write
    pFile = fopen(EepOptions.FileName, "wb");
    if (pFile == NULL) {
        return EEP_FAIL;
    }

    // Write buffer to file
    fwrite(
        pBuffer,        // Buffer to write
        sizeof(uint8_t),     // Item size
        EepSize,        // Buffer size
        pFile           // File pointer
        );

    // Close the file
    fclose(pFile);

    // Release the buffer
    if (pBuffer != NULL) {
        free(pBuffer);
    }

    printf("Ok (%s)\n", EepOptions.FileName);

    return EXIT_SUCCESS;
}

static uint8_t EepFile(void)
{
    printf("Function: %s\n", __func__);
    int status;

    // Attempt to set EEPROM address width if requested
    if (EepOptions.EepWidthSet != 0) {
        printf("Set address width..... \n");
        fflush(stdout);

        status = eep_set_address_width(EepOptions.EepWidthSet);

        if (0 == status) {
            printf("ERROR: Unable to set to %dB addressing\n", EepOptions.EepWidthSet);
            if (EepOptions.bIgnoreWarnings == false) {
                return EEP_WIDTH_ERROR;
            }
        } else {
            printf("Ok (%d-byte)\n", EepOptions.EepWidthSet);
        }
    }

    if (EepOptions.bLoadFile) {
        return EepromFileLoad();
    } else {
        return EepromFileSave();
    }
}

static void get_resource_name(struct pci_dev *p)
{
    char g_h1a_us_port_fname[17] = "\0";

    snprintf(g_h1a_us_port_fname,
             (int)sizeof(g_h1a_us_port_fname),
             "%04x:%02x:%02x.%d", 
             p->domain,
             p->bus,
             p->dev,
             p->func);

    snprintf(g_h1a_us_port_bar0,
             (int)sizeof(g_h1a_us_port_bar0),
             "/sys/bus/pci/devices/%s/resource0",
             g_h1a_us_port_fname);
}

static int eep_process(int j)
{
    struct device *d;
    int eep_present = EEP_PRSNT_MAX;
    int status = EXIT_SUCCESS;

    for (d=first_dev; d; d=d->next) {
        if (d->NumDevice == j) {
            get_resource_name(d->dev);
            eep_present = eep_read_status_reg();

            switch (eep_present) {
            case NOT_PRSNT:
                printf("No EEPROM Present\n");
                status = EXIT_FAILURE;
            break;
            case PRSNT_VALID:
                printf("EEPROM present with valid data\n");
            break;
            case PRSNT_INVALID:
                printf("Present but invalid data/CRC error/blank\n");
                eep_init();
                printf("EEPROM initialization done, please restart your computer.\n");
            break;
            }

            if (EXIT_SUCCESS == status) {
                status = EepFile();
            } else {
                return status;
            }
        }
    }
    return status;
}

static void DisplayHelp(void)
{
    printf(
        "\n"
        "EEPROM file utility for Adnacom devices.\n"
        "\n"
        " Usage: eep -l|-s file [-v]\n"
        "\n"
        " Options:\n"
        "   -l | -s       Load (-l) file to EEPROM -OR- Save (-s) EEPROM to file\n"
        "   file          Specifies the file to load or save\n"
        "   -v            Verbose output (for debug purposes)\n"
        "   -h or -?      This help screen\n"
        "\n"
        "  Sample command\n"
        "  -----------------\n"
        "  eep -l MyEeprom.bin\n"
        "\n"
        );
}

static uint8_t ProcessCommandLine(int argc, char *argv[])
{
    uint16_t i;
    char *pToken;
    bool bChipTypeValid;
    bool bGetFileName;
    bool bGetChipType;
    bool bGetEepWidth;
    bool bGetByteCount;
    bool bGetDeviceNum;

    bGetFileName  = false;
    bGetChipType  = false;
    bGetEepWidth  = false;
    bGetDeviceNum = false;
    bGetByteCount = false;

    for (i = 1; i < argc; i++) {
        if (bGetFileName) {
            if (argv[i][0] == '-') {
                printf("ERROR: File name not specified\n");
                return CMD_LINE_ERR;
            }

            // Get file name
            strcpy(EepOptions.FileName, argv[i]);

            // Flag parameter retrieved
            bGetFileName = false;
        } else if (bGetChipType) {
            if (argv[i][0] == '-') {
                printf("ERROR: PLX chip type not specified\n");
                return CMD_LINE_ERR;
            }

            // Get pointer to chip type
            pToken = strtok(argv[i], ", ");

            // Convert parameter to chip type
            EepOptions.LimitPlxChip = (u16)strtol(pToken, NULL, 16);

            // Get pointer to revision
            pToken = strtok(NULL, " ");

            // Convert to a revision if provided
            if (pToken != NULL) {
                EepOptions.LimitPlxRevision = (u8)strtol(pToken, NULL, 16);
            }

            // Default to valid chip type
            bChipTypeValid = true;

            // Verify supported chip type
            if ((EepOptions.LimitPlxChip & 0xFF00) != 0x8600) {
                bChipTypeValid = false;
            }

            if (bChipTypeValid == false) {
                printf("ERROR: Invalid PLX chip type\n");
                return CMD_LINE_ERR;
            }

            // Flag parameter retrieved
            bGetChipType = false;
        } else if (bGetEepWidth) {
            if (argv[i][0] == '-') {
                printf("ERROR: EEPROM address width override not specified\n");
                return CMD_LINE_ERR;
            }

            // Convert parameter to decimal
            EepOptions.EepWidthSet = atoi(argv[i]);

            // Flag parameter retrieved
            bGetEepWidth = false;
        } else if (bGetDeviceNum) {
            if (argv[i][0] == '-') {
                printf("ERROR: Device number not specified\n");
                return CMD_LINE_ERR;
            }

            // Convert parameter to decimal
            EepOptions.DeviceNumber = atoi(argv[i]);

            // Listing starts @ 1, so decrement since device list starts @ 0
            EepOptions.DeviceNumber--;

            // Flag parameter retrieved
            bGetDeviceNum = false;
        } else if (bGetByteCount) {
            if (argv[i][0] == '-') {
                printf("ERROR: Extra byte count not specified\n");
                return CMD_LINE_ERR;
            }

            // Convert parameter to decimal byte count
            EepOptions.ExtraBytes = (u16)atol(argv[i]);

            if (EepOptions.ExtraBytes == 0) {
                printf("ERROR: Invalid extra byte count\n");
                return CMD_LINE_ERR;
            }

            // Flag parameter retrieved
            bGetByteCount = false;
        } else if ((strcasecmp(argv[i], "-?") == 0) ||
                   (strcasecmp(argv[i], "-h") == 0)) {
            
            DisplayHelp();
            return EXIT_FAILURE;
        } else if (strcasecmp(argv[i], "-v") == 0) {
            EepOptions.bVerbose = true;
        } else if (strcasecmp(argv[i], "-l") == 0) {
            EepOptions.bLoadFile = true;

            // Set flag to get file name
            bGetFileName = true;
        } else if (strcasecmp(argv[i], "-s") == 0) {
            EepOptions.bLoadFile = false;

            // Set flag to get file name
            bGetFileName = true;
        } else if (strcasecmp(argv[i], "-p") == 0) {
            bGetChipType = true;
        } else if (strcasecmp(argv[i], "-w") == 0) {
            bGetEepWidth = true;
        } else if (strcasecmp(argv[i], "-d") == 0) {
            bGetDeviceNum = true;
        } else if (strcasecmp(argv[i], "-n") == 0) {
            bGetByteCount = true;
        } else if (strcasecmp(argv[i], "-i") == 0) {
            EepOptions.bIgnoreWarnings = true;
        } else if (strcasecmp(argv[i], "-e") == 0) {
            EepOptions.bListOnly = true;
        } else {
            printf("ERROR: Invalid argument \'%s\'\n", argv[i]);
            return CMD_LINE_ERR;
        }

        // Make sure next parameter exists
        if ((i + 1) == argc) {
            if (bGetFileName) {
                printf("ERROR: File name not specified\n");
                return CMD_LINE_ERR;
            }

            if (bGetChipType) {
                printf("ERROR: PLX chip type not specified\n");
                return CMD_LINE_ERR;
            }

            if (bGetEepWidth) {
                printf("ERROR: EEPROM address width not specified\n");
                return CMD_LINE_ERR;
            }

            if (bGetDeviceNum) {
                printf("ERROR: Device number not specified\n");
                return CMD_LINE_ERR;
            }

            if (bGetByteCount) {
                printf("ERROR: Extra byte count not specified\n");
                return CMD_LINE_ERR;
            }
        }
    }

    // Make sure required parameters were provided
    if (EepOptions.bListOnly  == true) {
        // Allow list only
    } else if ((EepOptions.bLoadFile == 0xFF) || (EepOptions.FileName[0] == '\0')) {
        printf("ERROR: EEPROM operation not specified. Use 'adna -h' for usage.\n");
        return EXIT_FAILURE;
    } else {}

    return EXIT_SUCCESS;
}

/* Main */

int
main(int argc, char **argv)
{
  int i, j;
  char *msg;
  int NumDevices = 1;
  int status = EXIT_SUCCESS;

  if (argc == 2 && !strcmp(argv[1], "--version")) {
    puts("Adnacom version " ADNATOOL_VERSION);
    return 0;
  }

  status = ProcessCommandLine(argc, argv);
  if (status != EXIT_SUCCESS)
    exit(1);

  pacc = pci_alloc();
  pacc->error = die;
  pci_filter_init(pacc, &filter);

#ifndef ADNA
  while ((i = getopt(argc, argv, options)) != -1)
    switch (i)
      {
      case 'n':
	pacc->numeric_ids++;
	break;
      case 'v':
	verbose++;
	break;
      case 'b':
	pacc->buscentric = 1;
	break;
      case 's':
	if (msg = pci_filter_parse_slot(&filter, optarg))
	  die("-s: %s", msg);
	opt_filter = 1;
	break;
      case 'd':
	if (msg = pci_filter_parse_id(&filter, optarg))
	  die("-d: %s", msg);
	opt_filter = 1;
	break;
      case 'x':
	opt_hex++;
	break;
      case 'P':
	opt_path++;
	need_topology = 1;
	break;
      case 't':
	opt_tree++;
	need_topology = 1;
	break;
      case 'i':
        pci_set_name_list_path(pacc, optarg, 0);
	break;
      case 'm':
	opt_machine++;
	break;
      case 'p':
	opt_pcimap = optarg;
	break;
#ifdef PCI_OS_LINUX
      case 'k':
	opt_kernel++;
	break;
#endif
      case 'M':
	opt_map_mode++;
	break;
      case 'D':
	opt_domains = 2;
	break;
#ifdef PCI_USE_DNS
      case 'q':
	opt_query_dns++;
	break;
      case 'Q':
	opt_query_all = 1;
	break;
#else
      case 'q':
      case 'Q':
	die("DNS queries are not available in this version");
#endif
      default:
	if (parse_generic_option(i, pacc, optarg))
	  break;
      bad:
	fprintf(stderr, help_msg, pacc->id_file_name);
	return 1;
      }
  if (optind < argc)
    goto bad;

  if (opt_query_dns)
    {
      pacc->id_lookup_mode |= PCI_LOOKUP_NETWORK;
      if (opt_query_dns > 1)
	pacc->id_lookup_mode |= PCI_LOOKUP_REFRESH_CACHE;
    }
  if (opt_query_all)
    pacc->id_lookup_mode |= PCI_LOOKUP_NETWORK | PCI_LOOKUP_SKIP_LOCAL;
#else
  (void)(msg);
  (void)(i);
#endif
  verbose = 2; // very verbose by default
  pci_init(pacc);
#ifndef ADNA
  if (opt_map_mode)
    {
      if (need_topology)
	die("Bus mapping mode does not recognize bus topology");
      map_the_bus();
    }
  else
    {
#endif // ADNA
      scan_devices();
      sort_them(&NumDevices);
#ifndef ADNA
      if (need_topology)
	grow_tree();
      if (opt_tree)
	show_forest(opt_filter ? &filter : NULL);
      else
#endif
	show();
    // }

  // Check devices exist and one was selected
  if (NumDevices == 1) {
    printf("No Adnacom device detected.\n");
    goto __exit;
  }

  if (EepOptions.bListOnly == true) {
    goto __exit;
  }

  printf("[0] Cancel\n\n");
  do {
      printf("    Device selection --> ");
      if (scanf("%d", &j) <= 0)
      {
          // Added for compiler warning
      }
  } while (j > NumDevices);
  if (j == 0)
      goto __exit;
  status = eep_process(j);
  if (status == EXIT_FAILURE)
      goto __exit;

__exit:
  show_kernel_cleanup();
  pci_cleanup(pacc);

  return (seen_errors ? 2 : 0);
}
