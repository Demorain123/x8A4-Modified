//
// Created by cryptic on 12/19/24.
//

/**
 * @file nvram.c
 * @author Cryptiiiic
 * @brief This file is for all kernel nvram related code.
 * @version 1.0.1
 * @date 2024-12-19
 *
 * @copyright Copyright (c) 2024
 */

/* Include headers */
#include <libkrw.h>
#include <x8A4/Kernel/kernel.h>
#include <x8A4/Kernel/offsets.h>
#include <x8A4/Kernel/nvram.h>
#include <x8A4/Kernel/osobject.h>
#include <x8A4/Logger/logger.h>
#include <x8A4/x8A4.h>

/* Cached Variables */
struct nvram_key *nvram_keys_cached;
int nvram_keys_count_cached = -1;

/* Functions */
/**
 * @brief           Gets a service's nvram dict from it's kobject
 * @param[in]       service
 * @return          Address of the nvram dict
 */
uint64_t get_service_nvram_dict(io_service_t service) {
  uint64_t kobject = get_ipc_kobject(service);
  if (!kobject) {
    x8A4_log_error("Kobject is NULL!\n", "");
    return 0;
  }
  uint64_t nvram_dict = 0;
  int ret = kread(kobject + koffsets_cached->io_dt_nvram, &nvram_dict, 8);
  if (ret || !nvram_dict) {
    x8A4_log_error("Failed to read kernel nvram dict from kobject! (%d: 0x%016llX)\n", ret, nvram_dict);
    return 0;
  }
  return nvram_dict;
}

/**
 * @brief           Find key name in key name cache
 * @param[in]       key
 * @param[in]       type
 * @return          Name of the key
 */
const char *find_nvram_key(const char *key, enum nvram_key_type type) {
  if(!key || (strlen(key) == 0)) {
    return NULL;
  }
  if(!nvram_keys_cached) {
    return NULL;
  }
  for(int i = 0; i < nvram_keys_count_cached; i++) {
    if(nvram_keys_cached[i].type != type) {
      continue;
    }
    if(strlen(key) != strlen(nvram_keys_cached[i].key_original)) {
      continue;
    }
    if(strcmp(nvram_keys_cached[i].key_original, key) == 0 && strstr(nvram_keys_cached[i].key, key)) {
      return nvram_keys_cached[i].key;
    }
  }
  return NULL;
}

/**
 * @brief           Setup key name cache and get key name for type
 * @param[in]       key
 * @param[in]       type
 * @return          Name of the key
 */
const char *get_nvram_key(const char *key, enum nvram_key_type type) {
  if(!key || (strlen(key) == 0)) {
    return NULL;
  }
  if(!nvram_keys_cached || nvram_keys_count_cached == -1) {
    nvram_keys_cached = (struct nvram_key *)calloc(NVRAM_KEY_LIMIT, sizeof(struct nvram_key));
    nvram_keys_count_cached = 0;
  }
  if(!nvram_keys_cached) {
    x8A4_log_error("Failed to calloc memory for nvram keys!\n", "");
    return NULL;
  }
  const char *key_cached = find_nvram_key(key, type);
  if(key_cached) {
    return key_cached;
  }
  nvram_keys_cached[nvram_keys_count_cached].key_original = (char *)key;
  nvram_keys_cached[nvram_keys_count_cached].type = type;
  switch (type) {
    case KEY_NORMAL:
      nvram_keys_cached[nvram_keys_count_cached].key = (char *)key;
      gc_d_cached[gc_d_count_cached++] = (uint64_t)key;
      break;
    case KEY_SYSTEM:
      nvram_keys_cached[nvram_keys_count_cached].key = (char *)calloc(1, 100);
      snprintf(nvram_keys_cached[nvram_keys_count_cached].key, 100, "%s%s", kAppleSystemVarGUID, (char *)key);
      break;
    case KEY_NVRAM:
      nvram_keys_cached[nvram_keys_count_cached].key = (char *)calloc(1, 100);
      snprintf(nvram_keys_cached[nvram_keys_count_cached].key, 100, "%s%s", kAppleNVRAMGUID, (char *)key);
      break;
  }
  return nvram_keys_cached[nvram_keys_count_cached++].key;
}

/**
 * @brief           Get nvram entry bytes from matching key
 * @param[in]       nvram_dict
 * @param[in]       key
 * @param[in]       type
 * @param[out]      out_size
 * @return          Pointer to the nvram entry bytes
 */
uint8_t *get_nvram_entry_bytes(uint64_t nvram_dict, const char *key, enum os_type type,
                               uint32_t *out_size) {
  if (!out_size) {
    x8A4_log_error("Failed to continue with getting entry bytes, out_size is "
            "NULL!\n", "");
    return NULL;
  }
  uint64_t entry_addr = 0;
  for(int i = 0; i < 3; i++) {
    entry_addr = 0;
    const char *key_tmp = get_nvram_key(key, i);
    entry_addr = get_entry_from_os_dict(nvram_dict, type, key_tmp, out_size);
    if(entry_addr) {
      break;
    }
  }
  if (!entry_addr) {
    x8A4_log_error("Failed to get entry address from nvram dict!\n", "");
    return NULL;
  }
  if (!*out_size) {
    x8A4_log_error("Failed to entry size from nvram dict!\n", "");
    return NULL;
  }
  if(verbose_cached) {
    x8A4_log_debug("entry_addr: 0x%016llX\n", entry_addr);
    x8A4_log_debug("out_size: 0x%016llX\n",(uint64_t)out_size);
    x8A4_log_debug("out_size: 0x%08X\n", *out_size);
  }
  uint8_t *entry_bytes = (uint8_t *)calloc(1, *out_size + 1);
  int ret = kread(entry_addr, entry_bytes, *out_size);
  if (ret) {
    if (entry_bytes)
      free(entry_bytes);
    x8A4_log_error("Failed to read entry bytes from nvram dict! (%d:%s)\n", ret, strerror(ret));
    return NULL;
  }
  gc_cached[gc_count_cached++] = (uint64_t)entry_bytes;
  x8A4_log_debug_error("gc_cached[gc_count_cached++]: %d val: 0x%016llX\n", __LINE__, entry_bytes);
  return entry_bytes;
}

/**
 * @brief           Set nvram entry bytes for matching key
 * @param[in]       nvram_dict
 * @param[in]       key
 * @param[in]       entry_bytes
 * @param[in]       size
 * @param[in]       type
 * @return          Pointer to the modified nvram entry bytes
 */
/* Removed mutation API set_nvram_entry_bytes: read-only research build. */

