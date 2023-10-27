#ifndef __PCIMEM_H__
#define __PCIMEM_H__

#include <stdint.h>

int pcimem(int access, uint32_t reg, uint32_t data);

#endif /* __PCIMEM_H__ */