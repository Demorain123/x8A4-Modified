//
// Created by cryptic on 4/14/24.
//

/**
 * @file kernel.h
 * @author Cryptiiiic
 * @brief This file is the header file for kernel.c
 * @version 1.0.1
 * @date 2024-04-14
 *
 * @copyright Copyright (c) 2024
 */

#ifndef X8A4_KERNEL_H
#define X8A4_KERNEL_H

/* Include headers */
#include <x8A4/Services/services.h>

/* External prototypes */

/* Prototypes */
uint64_t krw_get_kbase(void);
int tfp0_init(void);
int xpf_init(void);
const char *get_kernel_path(void);
#if 0
const char *get_kernel_path_legacy2(void);
const char *get_kernel_path_legacy(void);
#endif
int kread_smr(uint64_t addr, uint64_t *value, size_t sz);
uint64_t unsign_ptr(uint64_t *addr);
uint64_t get_our_proc(void);
uint64_t get_our_task(void);
uint64_t get_ipc_port(mach_port_name_t port_name);
uint64_t get_ipc_kobject(io_service_t service);

/* Cached Variables */
extern char *kernel_path_cached;
extern uint64_t our_proc_cached;
extern uint64_t our_task_cached;

#endif // X8A4_KERNEL_H
