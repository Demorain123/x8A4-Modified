//
// Created by cryptic on 4/14/24.
//

/**
 * @file registry.h
 * @author Cryptiiiic
 * @brief This file is the header file for registry.c
 * @version 1.0.1
 * @date 2024-04-14
 *
 * @copyright Copyright (c) 2024
 */

#ifndef X8A4_REGISTRY_H
#define X8A4_REGISTRY_H

/* Include headers */
#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonCrypto.h>

/* External Variables */
extern const mach_port_t kIOMasterPortDefault;

/* Typedefs */
typedef mach_port_t io_object_t;
typedef io_object_t io_registry_entry_t;
typedef char io_string_t[512];
typedef uint32_t IOOptionBits;

/* External prototypes */
io_registry_entry_t IORegistryEntryFromPath(mach_port_t, const io_string_t);
extern CFTypeRef IORegistryEntryCreateCFProperty(io_registry_entry_t, CFStringRef, CFAllocatorRef, IOOptionBits);
extern kern_return_t IOObjectRelease(io_object_t kobject);

/* Defines */
#define kIODeviceTreePlane "IODeviceTree"
#define IO_OBJECT_NULL ((io_object_t)0)
#define kIONVRAMDeletePropertyKey "IONVRAM-DELETE-PROPERTY"
#define kIONVRAMSyncNowPropertyKey "IONVRAM-SYNCNOW-PROPERTY"
#define kIONVRAMForceSyncNowPropertyKey "IONVRAM-FORCESYNCNOW-PROPERTY"

/* Prototypes */
io_registry_entry_t get_dtre_chosen(void);
io_registry_entry_t get_dtre_options(void);
CFDataRef get_hash_method_ref(void);
CFDataRef get_boot_manifest_hash_ref(void);
CFDataRef get_nonce_seeds_ref(void);
CFDataRef get_boot_nonce_ref(void);
uint32_t get_hash_method_len(void);
uint32_t get_boot_manifest_hash_len(void);
uint32_t get_nonce_seeds_len(void);
uint32_t get_boot_nonce_len(void);
const char *get_hash_method_registry(void);
const uint8_t *get_boot_manifest_hash_registry(void);
const uint8_t *get_nonce_seeds_registry(void);
const uint8_t *get_boot_nonce_registry(void);
uint32_t get_hash_len(void);

/* Cached Variables */
extern io_registry_entry_t chosen_cached;
extern io_registry_entry_t options_cached;
extern CFDataRef hash_method_ref_cached;
extern size_t hash_method_len_cached;
extern const char *hash_method_cached;
extern size_t hash_len_cached;

#endif // X8A4_REGISTRY_H
