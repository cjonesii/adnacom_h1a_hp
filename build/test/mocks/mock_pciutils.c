#include <string.h>
#include <stdlib.h>
#include <setjmp.h>
#include "cmock.h"
#include "mock_pciutils.h"


static struct mock_pciutilsInstance
{
  unsigned char placeHolder;
} Mock;

extern jmp_buf AbortFrame;
extern int GlobalExpectCount;
extern int GlobalVerifyOrder;

void mock_pciutils_Verify(void)
{
}

void mock_pciutils_Init(void)
{
  mock_pciutils_Destroy();
}

void mock_pciutils_Destroy(void)
{
  CMock_Guts_MemFreeAll();
  memset(&Mock, 0, sizeof(Mock));
  GlobalExpectCount = 0;
  GlobalVerifyOrder = 0;
}

