//
// Created by cryptic on 12/19/24.
//

/**
 * @file nvram.h
 * @author Cryptiiiic
 * @brief This file is the header file for nvram.c
 * @version 1.0.1
 * @date 2024-12-19
 *
 * @copyright Copyright (c) 2024
 */

#ifndef X8A4_NVRAM_H
#define X8A4_NVRAM_H

#include <x8A4/Services/services.h>
#include <x8A4/Kernel/osobject.h>

/* Enum Variables */
enum nvram_key_type {
  KEY_NORMAL = 0,
  KEY_SYSTEM,
  KEY_NVRAM,
};

/* Structure Variables */
struct nvram_key {
  enum nvram_key_type type;
  char *key_original;
  char *key;
};

/* Defines */
#define NVRAM_KEY_LIMIT 100
#define kAppleSystemVarGUID "40A0DDD2-77F8-4392-B4A3-1E7304206516:"
#define kAppleNVRAMGUID "7C436110-AB2A-4BBB-A880-FE41995C9F82:"
#define kNonceSeedsPropertyKey "nonce-seeds"
#define kKRNC1BTPropertyKey "krn.c1bt"
#define kBootNoncePropertyKey "com.apple.System.boot-nonce"

/* Prototypes */
uint64_t get_service_nvram_dict(io_service_t service);
uint8_t *get_nvram_entry_bytes(uint64_t nvram_dict, const char *key, enum os_type type, uint32_t *out_size);

/* Cached Variables */
extern struct nvram_key *nvram_keys_cached;
extern int nvram_keys_count_cached;

#endif // X8A4_NVRAM_H
