#ifndef COMMON_H
#define COMMON_H

void die(char *msg, ...) NONRET PCI_PRINTF(1,2);
void *xmalloc(size_t howmuch);
void *xrealloc(void *ptr, size_t howmuch);
char *xstrdup(const char *str);
int parse_generic_option(int i, struct pci_access *pacc, char *arg);

#endif // COMMON_H
