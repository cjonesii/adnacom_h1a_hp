#include "eep.h"
#include "pcimem.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "lspci.h"

extern struct eep_options EepOptions;

static void check_for_ready_or_done(void)
{
    volatile int eepCmdStatus = EEP_CMD_STAT_MAX;

    do {
        for (volatile int delay = 0; delay < 5000; delay++) {}
        eepCmdStatus = (pcimem(REG_READ, EEP_STAT_N_CTRL_ADDR, 0) >> EEP_CMD_STATUS_OFFSET) & 1;
    } while (CMD_COMPLETE != eepCmdStatus);
    if (EepOptions.bVerbose)
        printf("Controller is ready\n");
}

static void eep_data(uint32_t cmd, uint32_t *buffer)
{
    if (EepOptions.bVerbose)
        printf("Function: %s\n", __func__);

    check_for_ready_or_done();
    if (EepOptions.bVerbose)
        printf("  EEPROM Control: 0x%08x\n", cmd);
    pcimem(REG_WRITE, EEP_STAT_N_CTRL_ADDR, cmd);
    check_for_ready_or_done();

    if (RD_4B_FR_BLKADDR_TO_BUFF == ((cmd >> EEP_CMD_OFFSET) & 0x7)) {
        *buffer = pcimem(REG_READ, EEP_BUFFER_ADDR, 0);
        if (EepOptions.bVerbose)
            printf("Read buffer: 0x%08x\n", *buffer);
    }
}

int eep_read_status_reg(void)
{
    int eepPresent = EEP_PRSNT_MAX;
    /* Read the Serial EEPROM Status and Control register */
    eepPresent = ((pcimem(REG_READ, EEP_STAT_N_CTRL_ADDR, 0)) >> EEP_PRSNT_OFFSET) & 3;
    fflush(stdout);
    return eepPresent;
}

int eep_set_address_width(uint8_t width)
{
    if (EepOptions.bVerbose)
        printf("Function: %s\n", __func__);
    int status = 0;
    union eep_status_and_control_reg ctrl_reg = {0};

    ctrl_reg.cmd_n_status_struct.addr_width_override = ADDR_WIDTH_WRITABLE;
    status = pcimem(REG_WRITE, EEP_STAT_N_CTRL_ADDR, ctrl_reg.cmd_u32);
    ctrl_reg.cmd_n_status_struct.addr_width = width;
    status = pcimem(REG_WRITE, EEP_STAT_N_CTRL_ADDR, ctrl_reg.cmd_u32);

    fflush(stdout);
    return status;
}

void eep_read(uint32_t offset, uint32_t *read_buffer)
{
    if (EepOptions.bVerbose)
        printf("Function: %s\n", __func__);
    union eep_status_and_control_reg ctrl_reg = {0};
    // Section 6.8.2 step#2
    ctrl_reg.cmd_n_status_struct.cmd = RD_4B_FR_BLKADDR_TO_BUFF;
    ctrl_reg.cmd_n_status_struct.blk_addr = offset;
    // Section 6.8.2 step#3 and step#4
    eep_data(ctrl_reg.cmd_u32, read_buffer);
    fflush(stdout);
}

void eep_read_16(uint32_t offset, uint16_t *read_buffer)
{
    if (EepOptions.bVerbose)
        printf("Function: %s\n", __func__);
    union eep_status_and_control_reg ctrl_reg = {0};
    uint32_t buffer_32 = 0;

    ctrl_reg.cmd_n_status_struct.cmd = RD_4B_FR_BLKADDR_TO_BUFF;
    ctrl_reg.cmd_n_status_struct.blk_addr = offset;
    eep_data(ctrl_reg.cmd_u32, &buffer_32);

    *read_buffer = buffer_32 & 0xFFFF;
    fflush(stdout);
}

void eep_write(uint32_t offset, uint32_t write_buffer)
{
    if (EepOptions.bVerbose)
        printf("Function: %s\n", __func__);
    union eep_status_and_control_reg ctrl_reg = {0};

    check_for_ready_or_done();
    // Section 6.8.1 step#2
    pcimem(REG_WRITE, EEP_BUFFER_ADDR, write_buffer);
    check_for_ready_or_done();
    // Section 6.8.1 step#3
    ctrl_reg.cmd_n_status_struct.cmd = SET_WR_EN_LATCH;
    pcimem(REG_WRITE, EEP_STAT_N_CTRL_ADDR, ctrl_reg.cmd_u32);
    // Section 6.8.1 step#4
    ctrl_reg.cmd_n_status_struct.cmd = WR_4B_FR_BUFF_TO_BLKADDR;
    ctrl_reg.cmd_n_status_struct.blk_addr = offset;
    eep_data(ctrl_reg.cmd_u32, NULL);

    fflush(stdout);
}

void eep_write_16(uint32_t offset, uint16_t write_buffer)
{
    if (EepOptions.bVerbose)
        printf("Function: %s\n", __func__);
    union eep_status_and_control_reg ctrl_reg = {0};
    uint32_t buffer_32 = (uint32_t)write_buffer;

    check_for_ready_or_done();
    // Section 6.8.1 step#2
    pcimem(REG_WRITE, EEP_BUFFER_ADDR, buffer_32);
    check_for_ready_or_done();
    // Section 6.8.1 step#3
    ctrl_reg.cmd_n_status_struct.cmd = SET_WR_EN_LATCH;
    pcimem(REG_WRITE, EEP_STAT_N_CTRL_ADDR, ctrl_reg.cmd_u32);
    // Section 6.8.1 step#4
    ctrl_reg.cmd_n_status_struct.cmd = WR_4B_FR_BUFF_TO_BLKADDR;
    ctrl_reg.cmd_n_status_struct.blk_addr = offset;
    eep_data(ctrl_reg.cmd_u32, NULL);

    fflush(stdout);
}

void eep_init(void)
{
    if (EepOptions.bVerbose)
        printf("Function: %s\n", __func__);
    union eep_status_and_control_reg ctrl_reg = {0};

    // Section 6.8.3 step#2
    pcimem(REG_WRITE, EEP_BUFFER_ADDR, EEP_INIT_VAL);
    // Section 6.8.3 step#3
    ctrl_reg.cmd_n_status_struct.cmd = SET_WR_EN_LATCH;
    ctrl_reg.cmd_n_status_struct.addr_width_override = ADDR_WIDTH_WRITABLE;
    ctrl_reg.cmd_n_status_struct.addr_width = TWO_BYTES;
    pcimem(REG_WRITE, EEP_STAT_N_CTRL_ADDR, ctrl_reg.cmd_u32);
    // Section 6.8.3 step#4
    ctrl_reg.cmd_n_status_struct.cmd = WR_4B_FR_BUFF_TO_BLKADDR;
    ctrl_reg.cmd_n_status_struct.addr_width_override = ADDR_WIDTH_WRITABLE;
    ctrl_reg.cmd_n_status_struct.addr_width = TWO_BYTES;
    eep_data(ctrl_reg.cmd_u32, NULL);

    fflush(stdout);
}

