//
// Created by cryptic on 4/14/24.
//

/**
 * @file services.h
 * @author Cryptiiiic
 * @brief This file is the header file for services.c
 * @version 1.0.1
 * @date 2024-04-14
 *
 * @copyright Copyright (c) 2024
 */

#ifndef X8A4_SERVICES_H
#define X8A4_SERVICES_H

/* Include headers */
#include <x8A4/Registry/registry.h>
#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>

/* Typedefs */
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;

/* External prototypes */
io_service_t IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);
CFMutableDictionaryRef IOServiceMatching(const char *);
extern kern_return_t IOServiceOpen(io_service_t service, task_port_t task_port, uint32_t arg3, io_connect_t *service_out);
extern kern_return_t IOServiceClose(io_connect_t service);

/* Prototypes */
io_service_t get_io_aes_accel_service(void);

/* Cached Variables */
extern io_service_t io_aes_accel_service_cached;

#endif//X8A4_SERVICES_H
