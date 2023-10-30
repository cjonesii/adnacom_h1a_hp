#include "eep.h"
// #include "pcimem.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "adna.h"

extern struct eep_options EepOptions;
// extern struct device *first_dev;

static void check_for_ready_or_done(struct device *d, bool verbose)
{
    volatile uint32_t eepCmdStatus = EEP_CMD_STAT_MAX;

    do {
        for (volatile int delay = 0; delay < 5000; delay++) {}
        // eepCmdStatus = (pcimem(REG_READ, EEP_STAT_N_CTRL_ADDR, 0) >> EEP_CMD_STATUS_OFFSET) & 1;
        eepCmdStatus = (pci_eep_read_status_reg(d, EEP_STAT_N_CTRL_ADDR) >> EEP_CMD_STATUS_OFFSET) & 1;
    } while (CMD_COMPLETE != eepCmdStatus);
    if (verbose)
        printf("Controller is ready\n");
}

static void eep_data(struct device *d, uint32_t cmd, uint32_t *buffer, bool verbose)
{
    if (verbose)
        printf("Function: %s\n", __func__);

    check_for_ready_or_done(d, verbose);
    if (verbose)
        printf("  EEPROM Control: 0x%08x\n", cmd);
    // pcimem(REG_WRITE, EEP_STAT_N_CTRL_ADDR, cmd);
    check_for_ready_or_done(d, verbose);

    if (RD_4B_FR_BLKADDR_TO_BUFF == ((cmd >> EEP_CMD_OFFSET) & 0x7)) {
        // *buffer = pcimem(REG_READ, EEP_BUFFER_ADDR, 0);
        *buffer = pci_eep_read_status_reg(d, EEP_BUFFER_ADDR);
        if (verbose)
            printf("Read buffer: 0x%08x\n", *buffer);
    }
}

#ifndef ADNA
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
#endif // ADNA

void eep_read(struct device *d, uint32_t offset, uint32_t *read_buffer, bool verbose)
{
    if (verbose)
        printf("Function: %s\n", __func__);
    union eep_status_and_control_reg ctrl_reg = {0};
    // Section 6.8.2 step#2
    ctrl_reg.cmd_n_status_struct.cmd = RD_4B_FR_BLKADDR_TO_BUFF;
    ctrl_reg.cmd_n_status_struct.blk_addr = offset;
    // Section 6.8.2 step#3 and step#4
    eep_data(d, ctrl_reg.cmd_u32, read_buffer, verbose);
    fflush(stdout);
}

void eep_read_16(struct device *d, uint32_t offset, uint16_t *read_buffer, bool verbose)
{
    if (verbose)
        printf("Function: %s\n", __func__);
    union eep_status_and_control_reg ctrl_reg = {0};
    uint32_t buffer_32 = 0;

    ctrl_reg.cmd_n_status_struct.cmd = RD_4B_FR_BLKADDR_TO_BUFF;
    ctrl_reg.cmd_n_status_struct.blk_addr = offset;
    eep_data(d, ctrl_reg.cmd_u32, &buffer_32, verbose);

    *read_buffer = buffer_32 & 0xFFFF;
    fflush(stdout);
}

void eep_write(struct device *d, uint32_t offset, uint32_t write_buffer, bool verbose)
{
    if (verbose)
        printf("Function: %s\n", __func__);
    union eep_status_and_control_reg ctrl_reg = {0};

    check_for_ready_or_done(d, verbose);
    // Section 6.8.1 step#2
    // pcimem(REG_WRITE, EEP_BUFFER_ADDR, write_buffer);
    check_for_ready_or_done(d, verbose);
    // Section 6.8.1 step#3
    ctrl_reg.cmd_n_status_struct.cmd = SET_WR_EN_LATCH;
    // pcimem(REG_WRITE, EEP_STAT_N_CTRL_ADDR, ctrl_reg.cmd_u32);
    // Section 6.8.1 step#4
    ctrl_reg.cmd_n_status_struct.cmd = WR_4B_FR_BUFF_TO_BLKADDR;
    ctrl_reg.cmd_n_status_struct.blk_addr = offset;
    eep_data(d, ctrl_reg.cmd_u32, NULL, verbose);

    fflush(stdout);
}

void eep_write_16(struct device *d, uint32_t offset, uint16_t write_buffer, bool verbose)
{
    if (verbose)
        printf("Function: %s\n", __func__);
    union eep_status_and_control_reg ctrl_reg = {0};
    uint32_t buffer_32 = (uint32_t)write_buffer;

    check_for_ready_or_done(d, verbose);
    // Section 6.8.1 step#2
    // pcimem(REG_WRITE, EEP_BUFFER_ADDR, buffer_32);
    check_for_ready_or_done(d, verbose);
    // Section 6.8.1 step#3
    ctrl_reg.cmd_n_status_struct.cmd = SET_WR_EN_LATCH;
    // pcimem(REG_WRITE, EEP_STAT_N_CTRL_ADDR, ctrl_reg.cmd_u32);
    // Section 6.8.1 step#4
    ctrl_reg.cmd_n_status_struct.cmd = WR_4B_FR_BUFF_TO_BLKADDR;
    ctrl_reg.cmd_n_status_struct.blk_addr = offset;
    eep_data(d, ctrl_reg.cmd_u32, NULL, verbose);

    fflush(stdout);
}

void eep_init(struct device *d, bool verbose)
{
    if (verbose)
        printf("Function: %s\n", __func__);
    union eep_status_and_control_reg ctrl_reg = {0};

    // Section 6.8.3 step#2
    // pcimem(REG_WRITE, EEP_BUFFER_ADDR, EEP_INIT_VAL);
    // Section 6.8.3 step#3
    ctrl_reg.cmd_n_status_struct.cmd = SET_WR_EN_LATCH;
    ctrl_reg.cmd_n_status_struct.addr_width_override = ADDR_WIDTH_WRITABLE;
    ctrl_reg.cmd_n_status_struct.addr_width = TWO_BYTES;
    // pcimem(REG_WRITE, EEP_STAT_N_CTRL_ADDR, ctrl_reg.cmd_u32);
    // Section 6.8.3 step#4
    ctrl_reg.cmd_n_status_struct.cmd = WR_4B_FR_BUFF_TO_BLKADDR;
    ctrl_reg.cmd_n_status_struct.addr_width_override = ADDR_WIDTH_WRITABLE;
    ctrl_reg.cmd_n_status_struct.addr_width = TWO_BYTES;
    eep_data(d, ctrl_reg.cmd_u32, NULL, verbose);

    fflush(stdout);
}

