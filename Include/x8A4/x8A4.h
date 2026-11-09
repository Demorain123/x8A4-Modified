//
// Created by cryptic on 4/14/24.
//

/**
 * @file x8A4.h
 * @author Cryptiiiic
 * @brief This file is the header file for x8A4.c
 * @version 1.0.1
 * @date 2024-04-14
 *
 * @copyright Copyright (c) 2024
 */

#ifndef X8A4_X8A4_H
#define X8A4_X8A4_H

/* Include headers */
#include <stdint.h>
#include <x8A4/Kernel/kernel.h>
#include <x8A4/Kernel/kpf.h>
#include <x8A4/Kernel/offsets.h>
#include <x8A4/Kernel/slide.h>
#include <x8A4/Kernel/osobject.h>
#include <x8A4/Kernel/nvram.h>
#include <x8A4/Registry/registry.h>
#include <x8A4/Services/services.h>

/* Structure Variables */
struct x8A4_accel_key {
  uint32_t generated;
  uint32_t key_id;
  uint32_t key_sz;
  uint32_t key[4];
  uint32_t iv[4];
  uint32_t zero;
  uint32_t pad;
} __attribute__((packed, aligned(1)));

struct x8A4_nonce_domain {
  char *description;
  char *entitlement;
  uint64_t unknown_num;
  uint32_t *hash_length_function;
  uint32_t *domain_accessible_apshadow_function;
  uint64_t domain_index;
  uint64_t generate_flag;
  uint64_t io_aes_accel_key;
} __attribute__((packed, aligned(1)));

struct x8A4_nonce_descriptor {
  char *description;
  char unique_string[9];
  uint8_t pad[0x27];
  char *entitlement;
  uint64_t domain_index;
  uint64_t unknown_num1;
  uint64_t unknown_num2;
  uint64_t *nonce_domain_boot_select_chip_default_function;
  uint64_t *nonce_domain_boot_nonce_accessible_function;
} __attribute__((packed, aligned(1)));

struct x8A4_nonce_slot {
  struct x8A4_nonce_descriptor *nonce_slot_domain_descriptor;
  uint64_t *nonce_slot_init_function;
  uint64_t *nonce_slot_lock_function;
  uint64_t *nonce_slot_unlock_function;
  uint64_t *nonce_slot_data;
} __attribute__((packed, aligned(1)));

struct x8A4_nonce_seeds_header {
  uint32_t blob_version;
  uint8_t pad[6];
  uint64_t hash_size;
  uint8_t boot_manifest_hash[48];
  uint8_t end_data[9];
} __attribute__((packed, aligned(1)));

struct x8A4_nonce_seed {
  uint8_t unused_pad[8];
  uint8_t seed[16];
  uint8_t unused_end_pad[16];
} __attribute__((packed, aligned(1)));

struct x8A4_nonce_seeds {
  struct x8A4_nonce_seeds_header header;
  struct x8A4_nonce_seed seeds[];
} __attribute__((packed, aligned(1)));

struct x8A4_nonce_seeds_slot_header {
  uint8_t pad[4];
  uint8_t unknown_val;
} __attribute__((packed, aligned(1)));

struct x8A4_nonce_seeds_slot_seed {
  uint8_t seed[16];
  uint8_t pad[16];
} __attribute__((packed, aligned(1)));

struct x8A4_nonce_seeds_slot {
  struct x8A4_nonce_seeds_slot_header header;
  struct x8A4_nonce_seeds_slot_seed seed;
} __attribute__((packed, aligned(1)));

/* Defines */
#define X8A4_API_VERSION "1.0.1"
#define X8A4_ABI_VERSION SOVERSION

/* Prototypes */
__attribute__((used)) void x8A4_constructor(void);
__attribute__((used)) void x8A4_destructor(void);
int x8A4_init(void);
void x8A4_free(void);
const char *x8A4_version(void);
uint8_t *x8A4_get_nonce_slots_os_dict(uint32_t *seeds_size, int slot_index);
uint8_t *x8A4_get_nonce_seeds_os_dict(uint32_t *seeds_size);
uint8_t *x8A4_get_nonce_seeds_registry(uint32_t *seeds_size);
void x8A4_set_nonce_format(void);
uint8_t *x8A4_get_slot_seed(uint8_t **nonce_seeds, uint32_t *seeds_size, int slot_index);
uint8_t *x8A4_get_domain_seed(uint8_t **nonce_seeds, uint32_t *seeds_size, int domain_index);
struct x8A4_nonce_slot *x8A4_get_nonce_slots_list(void);
struct x8A4_nonce_domain *x8A4_get_nonce_seeds_domain_list(void);
int x8A4_get_domain_count(void);
int x8A4_get_domain_domains_index(const char *entitlement);
int x8A4_get_cryptex_boot_domain_domains_index(void);
int x8A4_get_cryptex_boot_slot_index(void);
int x8A4_get_cryptex_boot_domain_index(void);
uint8_t *x8A4_get_nonce_seeds(uint32_t *seeds_size);
uint8_t *x8A4_get_cryptex_seed(uint8_t **nonce_seeds, uint32_t *seeds_size);
uint8_t *x8A4_get_cryptex_nonce(uint32_t *nonce_size);
uint8_t *x8A4_get_boot_nonce_os_dict(uint32_t *generator_size);
uint8_t *x8A4_get_boot_nonce_registry(uint32_t *generator_size);
uint8_t *x8A4_get_apnonce_generator(uint32_t *generator_size);
uint8_t *x8A4_get_apnonce(uint32_t *apnonce_size);
struct x8A4_accel_key *x8A4_get_ioaesaccelkeys(uint32_t *keys_count);
void x8A4(void);
void x8A4_cli_set_verbose(void);
void x8A4_cli_get_cryptex_seed(void);
void x8A4_cli_get_cryptex_nonce(void);
void x8A4_cli_get_apnonce_generator(void);
void x8A4_cli_get_apnonce(void);
void x8A4_cli_get_accel_keys(uint32_t chosen_key);
void x8A4_cli_get_nonce_seeds(void);

/* Cached Variables */
extern int init_done;
extern struct x8A4_nonce_domain *domains_cached;
extern struct x8A4_nonce_slot *slots_cached;
extern int nonce_slot_format_cached;
extern int domains_count_cached;
extern int cryptex_domains_index_cached;
extern int cryptex_index_cached;
extern int verbose_cached;
extern uint64_t *gc_cached;
extern int gc_count_cached;
extern uint64_t *gc_d_cached;
extern int gc_d_count_cached;

#endif//X8A4_X8A4_H
