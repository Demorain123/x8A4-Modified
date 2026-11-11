//
// Created by cryptic on 4/14/24.
//

/**
 * @file registry.c
 * @author Cryptiiiic
 * @brief This file is for all registry related code.
 * @version 1.0.1
 * @date 2024-04-14
 *
 * @copyright Copyright (c) 2024
 */

/* Include headers */
#include <x8A4/Registry/registry.h>
#include <x8A4/Kernel/nvram.h>
#include <x8A4/x8A4.h>

/* Cached Variables */
io_registry_entry_t chosen_cached = IO_OBJECT_NULL;
io_registry_entry_t options_cached = IO_OBJECT_NULL;
CFDataRef hash_method_ref_cached = NULL;
CFDataRef boot_manifest_hash_ref_cached = NULL;
size_t hash_method_len_cached = 0;
size_t boot_manifest_hash_len_cached = 0;
const char *hash_method_cached = NULL;
const uint8_t *boot_manifest_hash_cached = NULL;
size_t hash_len_cached = 0;

/* Functions */
/**
 * @brief           Get DeviceTree's chosen entry
 * @return          DeviceTree chosen entry
 */
io_registry_entry_t get_dtre_chosen(void) {
  if (chosen_cached != IO_OBJECT_NULL) {
    IOObjectRelease(chosen_cached);
  }
  chosen_cached = IORegistryEntryFromPath(kIOMasterPortDefault,
                                          kIODeviceTreePlane ":/chosen");
  return chosen_cached;
}

/**
 * @brief           Get DeviceTree's options entry
 * @return          DeviceTree options entry
 */
io_registry_entry_t get_dtre_options(void) {
  if (options_cached != IO_OBJECT_NULL) {
    IOObjectRelease(options_cached);
  }
  options_cached = IORegistryEntryFromPath(kIOMasterPortDefault,
                                           kIODeviceTreePlane ":/options");
  return options_cached;
}

/**
 * @brief           Get hash method reference from DeviceTree's chosen
 * @return          Hash method reference
 */
CFDataRef get_hash_method_ref(void) {
  if (hash_method_ref_cached != NULL) {
    return hash_method_ref_cached;
  }
  io_registry_entry_t chosen = get_dtre_chosen();
  if (chosen == IO_OBJECT_NULL) {
    fprintf(stderr,
            "[-]: %s: Failed to get DeviceTree chosen entry from "
            "get_dtre_chosen()!\n",
            __FUNCTION__);
    return NULL;
  }
  CFDataRef hash_method_ref = NULL;
  hash_method_ref = IORegistryEntryCreateCFProperty(
      chosen, CFSTR("crypto-hash-method"), kCFAllocatorDefault, kNilOptions);
  if (hash_method_ref != NULL &&
      CFGetTypeID(hash_method_ref) == CFDataGetTypeID()) {
    hash_method_ref_cached = hash_method_ref;
    return hash_method_ref;
  } else {
    fprintf(
        stderr,
        "[-]: %s: Failed to get hash method from DeviceTree chosen entry!\n",
        __FUNCTION__);
  }
  return NULL;
}

/**
 * @brief           Get boot manifest hash reference from DeviceTree's chosen
 * @return          Boot manifest hash reference
 */
CFDataRef get_boot_manifest_hash_ref(void) {
  if (boot_manifest_hash_ref_cached != NULL) {
    return boot_manifest_hash_ref_cached;
  }
  io_registry_entry_t chosen = get_dtre_chosen();
  if (chosen == IO_OBJECT_NULL) {
    fprintf(stderr,
            "[-]: %s: Failed to get DeviceTree chosen entry from "
            "get_dtre_chosen()!\n",
            __FUNCTION__);
    return NULL;
  }
  CFDataRef boot_manifest_hash_ref = NULL;
  boot_manifest_hash_ref = IORegistryEntryCreateCFProperty(
      chosen, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, kNilOptions);
  if (boot_manifest_hash_ref != NULL &&
      CFGetTypeID(boot_manifest_hash_ref) == CFDataGetTypeID()) {
    boot_manifest_hash_ref_cached = boot_manifest_hash_ref;
    return boot_manifest_hash_ref;
  } else {
    fprintf(
        stderr,
        "[-]: %s: Failed to get boot_manifest_hash from DeviceTree chosen entry!\n",
        __FUNCTION__);
  }
  return NULL;
}

/**
 * @brief           Get nonce-seeds entry reference from DeviceTree's options
 * @return          Nonce-seeds reference
 */
CFDataRef get_nonce_seeds_ref(void) {
  io_registry_entry_t options = get_dtre_options();
  if (options == IO_OBJECT_NULL) {
    fprintf(stderr,
            "[-]: %s: Failed to get DeviceTree options entry from "
            "get_dtre_options()!\n",
            __FUNCTION__);
    return NULL;
  }
  CFDataRef nonce_seeds_ref = NULL;
  nonce_seeds_ref = IORegistryEntryCreateCFProperty(
      options, CFSTR(kNonceSeedsPropertyKey), kCFAllocatorDefault, kNilOptions);
  if (nonce_seeds_ref != NULL &&
      (CFGetTypeID(nonce_seeds_ref) == CFDataGetTypeID() || CFGetTypeID(nonce_seeds_ref) == CFStringGetTypeID())) {
    return nonce_seeds_ref;
  } else {
    if(verbose_cached) {
      if (nonce_seeds_ref == NULL) {
        fprintf(stderr, "[-]: %s: nonce_seeds_ref is NULL\n", __FUNCTION__);
      } else {
        fprintf(stderr, "[-]: %s: nonce_seeds_ref type is %lu\n", __FUNCTION__,
                CFGetTypeID(nonce_seeds_ref));
      }
    }
  }
  return NULL;
}

/**
 * @brief           Get boot-nonce entry reference from DeviceTree's options
 * @return          Boot-nonce reference
 */
CFDataRef get_boot_nonce_ref(void) {
  io_registry_entry_t options = get_dtre_options();
  if (options == IO_OBJECT_NULL) {
    fprintf(stderr,
            "[-]: %s: Failed to get DeviceTree options entry from "
            "get_dtre_options()!\n",
            __FUNCTION__);
    return NULL;
  }
  CFDataRef boot_nonce_ref = NULL;
  boot_nonce_ref = IORegistryEntryCreateCFProperty(
      options, CFSTR(kBootNoncePropertyKey), kCFAllocatorDefault, kNilOptions);
  if (boot_nonce_ref != NULL &&
      (CFGetTypeID(boot_nonce_ref) == CFDataGetTypeID() || CFGetTypeID(boot_nonce_ref) == CFStringGetTypeID())) {
    return boot_nonce_ref;
  } else {
    if(verbose_cached) {
      fprintf(
          stderr,
          "[-]: %s: Failed to get boot-nonce from DeviceTree options entry!\n",
          __FUNCTION__);
      if (boot_nonce_ref == NULL) {
        fprintf(stderr, "[-]: %s: boot_nonce_ref is NULL\n", __FUNCTION__);
      } else {
        fprintf(stderr, "[-]: %s: boot_nonce_ref type is %lu\n", __FUNCTION__,
                CFGetTypeID(boot_nonce_ref));
      }
    }
  }
  return NULL;
}

/**
 * @brief           Get length of hash method reference
 * @return          Length of hash method reference
 */
uint32_t get_hash_method_len(void) {
  if (hash_method_len_cached != 0) {
    return hash_method_len_cached;
  }
  CFDataRef hash_method_ref = get_hash_method_ref();
  if (hash_method_ref == NULL) {
    fprintf(stderr, "[-]: %s: Hash method reference is NULL!\n", __FUNCTION__);
    return 0;
  }
  uint32_t hash_method_len;
  hash_method_len = (uint32_t)CFDataGetLength(hash_method_ref);
  if (hash_method_len == 0) {
    fprintf(stderr,
            "[-]: %s: Failed to get hash method length from hash method "
            "reference!\n",
            __FUNCTION__);
    return 0;
  }
  hash_method_len_cached = hash_method_len;
  return hash_method_len;
}

/**
 * @brief           Get length of boot manifest hash reference
 * @return          Length of boot manifest hash reference
 */
uint32_t get_boot_manifest_hash_len(void) {
  if (boot_manifest_hash_len_cached != 0) {
    return boot_manifest_hash_len_cached;
  }
  CFDataRef boot_manifest_hash_ref = get_boot_manifest_hash_ref();
  if (boot_manifest_hash_ref == NULL) {
    fprintf(stderr, "[-]: %s:  reference is NULL!\n", __FUNCTION__);
    return 0;
  }
  uint32_t boot_manifest_hash_len;
  boot_manifest_hash_len = (uint32_t)CFDataGetLength(boot_manifest_hash_ref);
  if (boot_manifest_hash_len == 0) {
    fprintf(stderr,
            "[-]: %s: Failed to get  length from hash method "
            "reference!\n",
            __FUNCTION__);
    return 0;
  }
  boot_manifest_hash_len_cached = boot_manifest_hash_len;
  return boot_manifest_hash_len;
}

/**
 * @brief           Get length of nonce-seeds reference
 * @return          Length of nonce-seeds reference
 */
uint32_t get_nonce_seeds_len(void) {
  CFDataRef nonce_seeds_ref = get_nonce_seeds_ref();
  if (nonce_seeds_ref == NULL) {
    if(verbose_cached)
      fprintf(stderr, "[-]: %s: Nonce-seeds reference is NULL!\n", __FUNCTION__);
    return 0;
  }
  uint32_t nonce_seeds_len;
  if(CFGetTypeID(nonce_seeds_ref) == CFDataGetTypeID()) {
    nonce_seeds_len = (uint32_t)CFDataGetLength(nonce_seeds_ref);
  } else if(CFGetTypeID(nonce_seeds_ref) == CFStringGetTypeID()) {
    nonce_seeds_len = (uint32_t)CFStringGetLength((CFStringRef)nonce_seeds_ref);
  } else {
    return 0;
  }

  if (nonce_seeds_len == 0) {
    fprintf(stderr,
            "[-]: %s: Failed to get nonce-seeds length from nonce-seeds "
            "reference!\n",
            __FUNCTION__);
    return 0;
  }
  return nonce_seeds_len;
}

/**
 * @brief           Get length of boot-nonce reference
 * @return          Length of hash-seeds reference
 */
uint32_t get_boot_nonce_len(void) {
  CFDataRef boot_nonce_ref = get_boot_nonce_ref();
  if (boot_nonce_ref == NULL) {
    if(verbose_cached)
      fprintf(stderr, "[-]: %s: Boot-nonce reference is NULL!\n", __FUNCTION__);
    return 0;
  }
  uint32_t boot_nonce_len = 0;
  if(CFGetTypeID(boot_nonce_ref) == CFDataGetTypeID()) {
    boot_nonce_len = (uint32_t)CFDataGetLength((CFDataRef)boot_nonce_ref);
  } else if(CFGetTypeID(boot_nonce_ref) == CFStringGetTypeID()) {
    boot_nonce_len = (uint32_t)CFStringGetLength((CFStringRef)boot_nonce_ref);
  } else {
    fprintf(stderr,
            "[-]: %s: Boot-nonce reference is unsupported CF Type! (%lu)\n",
            __FUNCTION__, CFGetTypeID(boot_nonce_ref));
  }
  if (boot_nonce_len == 0) {
    if(verbose_cached)
      fprintf(stderr,
              "[-]: %s: Failed to get boot-nonce length from boot-nonce "
              "reference!\n",
              __FUNCTION__);
    return 0;
  }
  return boot_nonce_len;
}

/**
 * @brief           Get hash method string from hash method reference
 * @return          Hash method string
 */
const char *get_hash_method_registry(void) {
  if (hash_method_cached) {
    return hash_method_cached;
  }
  CFDataRef hash_method_ref = get_hash_method_ref();
  if (hash_method_ref == NULL) {
    fprintf(stderr, "[-]: %s: Hash method ref is NULL!\n", __FUNCTION__);
    return NULL;
  }
  const char *hash_method = (const char *)CFDataGetBytePtr(hash_method_ref);
  if (hash_method == NULL) {
    fprintf(stderr,
            "[-]: %s: Failed to get hash method string from hash method ref!\n",
            __FUNCTION__);
    return NULL;
  }
  if (hash_method[get_hash_method_len() - 1] != '\0') {
    fprintf(stderr, "[-]: %s: Hash method string is a corrupt string!\n",
            __FUNCTION__);
    return NULL;
  }
  hash_method_cached = hash_method;
  return hash_method;
}

/**
 * @brief           Get  string from boot manifest hash reference
 * @return          Boot manifest hash string
 */
const uint8_t *get_boot_manifest_hash_registry(void) {
  if (boot_manifest_hash_cached) {
    return boot_manifest_hash_cached;
  }
  CFDataRef boot_manifest_hash_ref = get_boot_manifest_hash_ref();
  if (boot_manifest_hash_ref == NULL) {
    fprintf(stderr, "[-]: %s:  ref is NULL!\n", __FUNCTION__);
    return NULL;
  }
  const uint8_t *boot_manifest_hash = (const uint8_t *)CFDataGetBytePtr(boot_manifest_hash_ref);
  if (boot_manifest_hash == NULL) {
    fprintf(stderr,
            "[-]: %s: Failed to get  string from  ref!\n",
            __FUNCTION__);
    return NULL;
  }
  boot_manifest_hash_cached = boot_manifest_hash;
  return boot_manifest_hash;
}

/**
 * @brief           Get nonce-seeds bytes from nonce-seeds reference
 * @return          Nonce-seeds bytes
 */
const uint8_t *get_nonce_seeds_registry(void) {
  CFDataRef nonce_seeds_ref = get_nonce_seeds_ref();
  if (nonce_seeds_ref == NULL) {
    fprintf(stderr, "[-]: %s: Nonce-seeds reference is NULL!\n", __FUNCTION__);
    return NULL;
  }
  uint8_t *nonce_seeds_tmp = NULL;
  if(CFGetTypeID(nonce_seeds_ref) == CFDataGetTypeID()) {
    nonce_seeds_tmp = (uint8_t *)CFDataGetBytePtr(nonce_seeds_ref);
  } else if(CFGetTypeID(nonce_seeds_ref) == CFStringGetTypeID()) {
    nonce_seeds_tmp = (uint8_t *)CFStringGetCStringPtr((CFStringRef)nonce_seeds_ref, kCFStringEncodingASCII);
  } else {
    return 0;
  }
  const uint8_t *nonce_seeds = nonce_seeds_tmp;
  if (!nonce_seeds) {
    fprintf(stderr, "[-]: %s: Nonce-seeds is NULL!\n", __FUNCTION__);
  }
  return nonce_seeds;
}

/**
 * @brief           Get boot-nonce bytes from boot-nonce reference
 * @return          Boot-nonce bytes
 */
const uint8_t *get_boot_nonce_registry(void) {
  void *boot_nonce_ref = (void *)get_boot_nonce_ref();
  if (boot_nonce_ref == NULL) {
    fprintf(stderr, "[-]: %s: Boot-nonce reference is NULL!\n", __FUNCTION__);
    return NULL;
  }
  uint8_t *boot_nonce_tmp = NULL;
  if (CFGetTypeID(boot_nonce_ref) == CFDataGetTypeID()) {
    boot_nonce_tmp = (uint8_t *)CFDataGetBytePtr(boot_nonce_ref);
  } else if (CFGetTypeID(boot_nonce_ref) == CFStringGetTypeID()) {
    boot_nonce_tmp = (uint8_t *)CFStringGetCStringPtr(boot_nonce_ref,
                                                      kCFStringEncodingASCII);
  } else {
    fprintf(stderr,
            "[-]: %s: Boot-nonce reference is unsupported CF Type! (%lu)\n",
            __FUNCTION__, CFGetTypeID(boot_nonce_ref));
  }
  if (!boot_nonce_tmp) {
    fprintf(stderr, "[-]: %s: Boot-nonce is NULL!\n", __FUNCTION__);
  }
  const uint8_t *boot_nonce = (const uint8_t *)boot_nonce_tmp;
  return boot_nonce;
}

/**
 * @brief           Get length of hash based on hash method string
 * @return          Length of hash
 */
uint32_t get_hash_len(void) {
  if (hash_len_cached != 0) {
    return hash_len_cached;
  }
  const char *hash_method = get_hash_method_registry();
  if (hash_method == NULL) {
    fprintf(stderr, "[-]: %s: Hash method string is NULL!\n", __FUNCTION__);
    return 0;
  }
  if (strcmp(hash_method, "sha1") == 0) {
    hash_len_cached = CC_SHA1_DIGEST_LENGTH;
    return CC_SHA1_DIGEST_LENGTH;
  } else if (strcmp(hash_method, "sha2-384") == 0) {
    hash_len_cached = CC_SHA384_DIGEST_LENGTH;
    return CC_SHA384_DIGEST_LENGTH;
  }
  fprintf(stderr, "[-]: %s: Unknown hash method (%s)!\n", __FUNCTION__,
          hash_method);
  return 0;
}

/**
 * @brief           Set an nvram registry entry via DeviceTree's options
 * @param[in]       nvram_entry
 * @param[in]       key
 * @param[in]       value
 * @return          Zero on success
 */
/* Removed mutation API set_nvram_entry: read-only research build. */

