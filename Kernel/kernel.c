//
// Created by cryptic on 4/14/24.
//

/**
 * @file kernel.c
 * @author Cryptiiiic
 * @brief This file is for all kernel related code.
 * @version 1.0.1
 * @date 2024-04-14
 *
 * @copyright Copyright (c) 2024
 */

/* Include headers */
#include <libkrw.h>
#include <sys/mount.h>
#include <x8A4/Kernel/kernel.h>
#include <x8A4/Kernel/offsets.h>
#include <x8A4/Kernel/slide.h>
#include <x8A4/Services/services.h>
#include <x8A4/Registry/registry.h>
#include <x8A4/Logger/logger.h>
#include <x8A4/x8A4.h>

/* Cached Variables */
char *kernel_path_cached = NULL;
uint64_t our_proc_cached = 0;
uint64_t our_task_cached = 0;

/* Functions */
/**
 * @brief           Get kernel's base from the libkrw library.
 * @return          Kernel base, zero on failure
 */
uint64_t krw_get_kbase(void) {
  uint64_t base = 0;
  if (kbase(&base) || !base) {
    x8A4_log_error("Failed get kernel base!\n", "");
    return 0;
  }
  return base;
}

/**
 * @brief           Verifies if tfp0 kread works
 * @return          Zero on kread success
 */
int tfp0_init(void) {
  uint32_t read_bytes = 0;
  uint64_t base = 0;
  int ret = kbase(&base);
  if (ret != 0) {
    x8A4_log_error("Kernel read provider kbase failed.\n", "");
    return -1;
  }
  x8A4_log_debug("kbase ret: %d kbase: 0x%016llX!\n", ret, base);
  if (!base) {
    base = gXPF.kernelBase + get_slide();
  }
  if(kread(base, &read_bytes, 4) || read_bytes != 0xFEEDFACF) {
    x8A4_log_error("Failed kread at kbase: 0x%016llX!\n", base);
    return -1;
  }
  return 0;
}

/**
 * @brief           Initializes XPF lib with filesystem kernel
 * @return          Zero on XPF init success
 */
int xpf_init(void) {
  const char *path = get_kernel_path();
  if (!path) return -1;
  int ret = xpf_start_with_kernel_path(path);
  const char *err = xpf_get_error();
  if(err) {
    x8A4_log_error("Can't proceed with kernel init, failed to start xpf with kernel: \"%s\" error: %s\n", get_kernel_path(), err);
  }
  if(!ret) {
    x8A4_set_nonce_format();
  }
  return ret;
}
// int xpf_init(void) { return
// xpf_start_with_kernel_path(get_kernel_path_legacy()); }

/**
 * @brief           Get the path to the filesystem kernel inside preboot
 * @return          Kernel path
 */
const char *get_kernel_path(void) {
  if (kernel_path_cached) return kernel_path_cached;
  const uint8_t *hash = get_boot_manifest_hash_registry();
  const uint32_t hash_len = get_boot_manifest_hash_len();
  if (!hash || (hash_len != CC_SHA1_DIGEST_LENGTH &&
                hash_len != CC_SHA384_DIGEST_LENGTH)) {
    x8A4_log_error("Unsupported or unavailable boot manifest hash.\n", "");
    return NULL;
  }
  char hex[2 * CC_SHA384_DIGEST_LENGTH + 1];
  static const char digits[] = "0123456789ABCDEF";
  for (uint32_t i = 0; i < hash_len; i++) {
    hex[2*i] = digits[hash[i] >> 4];
    hex[2*i + 1] = digits[hash[i] & 15];
  }
  hex[2*hash_len] = '\0';
  const char *fmt = "/private/preboot/%s/System/Library/Caches/"
                    "com.apple.kernelcaches/kernelcache";
  char *path = calloc(1, 256);
  if (!path) return NULL;
  int n = snprintf(path, 256, fmt, hex);
  if (n < 0 || n >= 256 || access(path, R_OK) != 0) {
    x8A4_log_error("Preboot kernelcache path missing or inaccessible.\n", "");
    free(path);
    return NULL;
  }
  kernel_path_cached = path;
  return path;
}

#if 0
/**
 * @brief           Reads mntinfo firmware entry to find preboot kernel path
 * @return          Kernel path
 */
const char *get_kernel_path_legacy2(void) {
  if (kernel_path_cached) {
    return kernel_path_cached;
  }
  const char *preboot_path = "/private/preboot/";
  if (access(preboot_path, F_OK) != 0) {
    x8A4_log_error("Can't proceed with kernel init, %s not found!\n", preboot_path);
    return NULL;
  }

  int mnt_size = 0;
  struct statfs *mnt_buf = NULL;
  mnt_size = getmntinfo(&mnt_buf, MNT_NOWAIT);
  char *preboot_path_hash = NULL;
  for (int i = 0; i < mnt_size; i++) {
    if (strcmp(mnt_buf[i].f_mntonname, "/usr/standalone/firmware") == 0) {
      void *mnt_off = &mnt_buf[i].f_mntfromname;
      void *end_off =
          strstr(mnt_buf[i].f_mntfromname, "/usr/standalone/firmware");
      if (end_off) {
        preboot_path_hash = mnt_buf[i].f_mntfromname;
        preboot_path_hash[end_off - mnt_off] = '\0';
      }
      break;
    }
  }
  if (!preboot_path_hash) {
    x8A4_log_error("Failed to get preboot path boot_manifest_hash!\n", "");
    return NULL;
  }

  const char *format = "%s/System/Library/Caches/"
                       "com.apple.kernelcaches/kernelcache";
  char *kernel_path = (char *)calloc(1, 256);
  snprintf(kernel_path, 256, format, preboot_path_hash);
  kernel_path_cached = kernel_path;
  return (const char *)kernel_path;
}

/**
 * @brief           Reads active preboot to find kernel path
 * @return          Kernel path
 */
const char *get_kernel_path_legacy(void) {
  if (kernel_path_cached) {
    return kernel_path_cached;
  }
  const char *active_path = "/private/preboot/active";
  if (access(active_path, F_OK) != 0) {
    fprintf(stderr, "[-]: %s: Can't proceed with kernel init, %s not found!\n",
            __FUNCTION__, active_path);
    return NULL;
  }
  FILE *active_file = fopen(active_path, "r");
  if (active_file == NULL) {
    fprintf(stderr, "[-]: %s: Failed to open file %s!\n", __FUNCTION__,
            active_path);
    return NULL;
  }
  size_t active_file_size;
  fseek(active_file, 0, SEEK_END);
  active_file_size = ftell(active_file);
  if (active_file_size == 0) {
    fprintf(stderr, "[-]: %s: File %s is somehow empty!\n", __FUNCTION__,
            active_path);
    fclose(active_file);
    return NULL;
  }
  fseek(active_file, 0, SEEK_SET);
  char *hash = (char *)calloc(1, active_file_size + 1);
  size_t ret = fread(hash, 1, active_file_size, active_file);
  fclose(active_file);
  if (ret != active_file_size) {
    fprintf(stderr, "[-]: %s Only read %zu bytes from %s!\n", __FUNCTION__, ret,
            active_path);
    return NULL;
  }
  const char *format = "/private/preboot/%s/System/Library/Caches/"
                       "com.apple.kernelcaches/kernelcache";
  char *kernel_path = (char *)calloc(1, PATH_MAX);
  snprintf(kernel_path, PATH_MAX, format, hash);
  kernel_path_cached = kernel_path;
  return (const char *)kernel_path;
}
#endif

/**
 * @brief           Kernel kread wrapper for reading from SMR pointers
 * @param[in]       addr
 * @param[out]      value
 * @param[in]       sz
 * @return          Zero on success
 */
int kread_smr(uint64_t addr, uint64_t *value, size_t sz) {
  if (!value || sz != sizeof(*value) || !koffsets_cached ||
      !koffsets_cached->t1sz_boot || koffsets_cached->t1sz_boot > 62 ||
      !koffsets_cached->smr || koffsets_cached->smr > 3)
    return -1;
  int ret = kread(addr, value, sz);
  if (ret) {
    x8A4_log_error("Failed to read kernel smr pointer 0x%llX 0x%zX(%d)\n", addr, sz, ret);
    return -1;
  }
  if (!unsign_ptr(value)) return -1;
  uint64_t bits = (koffsets_cached->smr << (62 - koffsets_cached->t1sz_boot));
  uint64_t case1 = 0xFFFFFFFFFFFFC000 & ~bits;
  uint64_t case2 = 0xFFFFFFFFFFFFFFE0 & ~bits;
  if ((*value & bits) == 0) {
    if (*value) {
      *value = (*value & case1) | bits;
    }
  } else {
    *value = (*value & case2) | bits;
  }
  return 0;
}

/**
 * @brief           Unsign a PAC signed pointer addr with t1sz
 * @param[in]       addr
 * @return          Unsigned addr
 */
uint64_t unsign_ptr(uint64_t *addr) {
  if (!addr) {
    return 0;
  }
  if (!*addr || !koffsets_cached || !koffsets_cached->t1sz_boot ||
      koffsets_cached->t1sz_boot > 62) {
    return 0;
  }
  *addr |= ~((1ULL << (64U - koffsets_cached->t1sz_boot)) - 1U);
  return *addr;
}

/**
 * @brief           Traverses kernel proc struct to find our pid's proc entry
 * @return          Address of our proc's proc entry
 */
uint64_t get_our_proc(void) {
  if (our_proc_cached) {
    return our_proc_cached;
  }
  const pid_t our_pid = getpid();
  pid_t pid = 0;
  uint64_t proc = koffsets_cached->all_proc + get_slide();
  bool found = false;
  /* Reject cyclic/broken lists instead of looping indefinitely. */
  for (uint32_t inspected = 0; inspected < 262144 && proc; ++inspected) {
    uint64_t next = 0;
    if (kread(proc + koffsets_cached->proc_list_next, &next, sizeof(next)))
      break;
    if (!unsign_ptr(&next) || next == proc) break;
    proc = next;
    if (kread(proc + koffsets_cached->proc_pid, &pid, sizeof(pid))) break;
    if (pid == our_pid) {
      found = true;
      break;
    }
  }
  if (!found) {
    x8A4_log_error("Failed to find ourproc in kernel allproc!\n", "");
  }
  return found ? proc : 0;
}

/**
 * @brief           Gets our task struct from our proc
 * @return          Address of our proc's task struct
 */
uint64_t get_our_task(void) {
  if (our_task_cached) {
    return our_task_cached;
  }
  uint64_t proc = get_our_proc();
  if (proc == 0) {
    x8A4_log_error("Ourproc is zero!\n", "");
    return 0;
  }
  if (strcmp(gXPF.darwinVersion, "22.0.0") >= 0) {
    our_task_cached = proc + koffsets_cached->proc_struct_size;
  } else {
    int ret = kread(proc + koffsets_cached->proc_task, &proc, 8);
    if (ret || !proc) {
      x8A4_log_error("Failed to read from proc proc_task! (%d:0x%016llX)\n", ret, proc);
      return 0;
    }
    our_task_cached = proc;
    return proc;
  }
  return proc + koffsets_cached->proc_struct_size;
}

/**
 * @brief           Get ipc_port address a from port name
 * @param[in]       port_name
 * @return          Address of an ipc_port in kernel space
 */
uint64_t get_ipc_port(mach_port_name_t port_name) {
  if (MACH_PORT_VALID(port_name) == 0) {
    x8A4_log_error("Port 0x%X is invalid!\n", port_name);
    return 0;
  }
  uint64_t task = get_our_task();
  if (task == 0) {
    x8A4_log_error("Task is NULL!\n", "");
    return 0;
  }
  uint64_t itk_space = 0;
  int ret = kread(task + koffsets_cached->itk_space, &itk_space, 8);
  if (ret || !itk_space) {
    x8A4_log_error("Failed to read kernel task itk_space! (%d:0x%016llX)\n", ret, itk_space);
    return 0;
  }
  if (!unsign_ptr(&itk_space)) {
    x8A4_log_error("Kernel task itk_space pointer is invalid after normalization.\n", "");
    return 0;
  }
  uint64_t table = 0;
  if (koffsets_cached->table_smr) {
    ret =
        kread_smr(itk_space + koffsets_cached->task_itk_space_table, &table, 8);
  } else {
    ret = kread(itk_space + koffsets_cached->task_itk_space_table, &table, 8);
  }
  if (ret || !table) {
    x8A4_log_error("Failed to read kernel task itk_space table! (%d:0x%016llX)\n", ret, table);
    return 0;
  }
  if (!unsign_ptr(&table)) {
    x8A4_log_error("Kernel IPC table pointer is invalid after normalization.\n", "");
    return 0;
  }
  uint64_t port = 0;
  ret = kread(
      table + (MACH_PORT_INDEX(port_name) * koffsets_cached->ipc_entry_size) +
          koffsets_cached->ipc_entry_object,
      &port, 8);
  if (ret || !unsign_ptr(&port)) {
    x8A4_log_error("Failed to read or normalize port from kernel ipc_entry object! (%d)\\n", ret);
    return 0;
  }
  return port;
}

/**
 * @brief           Gets the ipc_kobject from the IOMachPort address
 * @param[in]       port_addr
 * @return          Address of kobject in kernel space
 */
uint64_t get_ipc_kobject_from_iomachport(uint64_t port_addr) {
  if (!koffsets_cached->ipc_port_kobject_is_iomachport) {
    x8A4_log_error("Ipc_kobject is not wrapped by IOMachPort on this version!\n", "");
    return 0;
  }
  if (!unsign_ptr(&port_addr)) {
    x8A4_log_error("IOMachPort port address is invalid after normalization.\n", "");
    return 0;
  }
  uint64_t kobject = 0;
  int ret = kread(port_addr + koffsets_cached->iomachport_object, &kobject, 8);
  if (ret || !unsign_ptr(&kobject)) {
    x8A4_log_error("Failed to read or normalize IOMachPort object! (%d)\n", ret);
    return 0;
  }
  return kobject;
}

/**
 * @brief           Gets a service's kobject from an ipc_port address
 * @param[in]       service
 * @return          Address of kobject in kernel space
 */
uint64_t get_ipc_kobject(io_service_t service) {
  uint64_t port = get_ipc_port(service);
  if (port == 0) {
    x8A4_log_error("Ipc port address is zero!\n", "");
    return 0;
  }
  uint64_t kobject = 0;
  int ret = kread(port + koffsets_cached->ipc_port_kobject, &kobject, 8);
  if (ret || !unsign_ptr(&kobject)) {
    x8A4_log_error("Failed to read or normalize kobject from ipc port! (%d)\n", ret);
    return 0;
  }
  if (koffsets_cached->ipc_port_kobject_is_iomachport) {
    kobject = get_ipc_kobject_from_iomachport(kobject);
  }
  return kobject;
}

#if 0
/**
 * @brief           Test code to get current expert pointer
 */
__unused uint64_t get_generic_expert_current(void) {
  int ret = 0;
  uint64_t genx_addr = 0xFFFFFFF007ADD998 + get_slide();
  if (!genx_addr) {
    return 0;
  }
  uint64_t genx = 0;
  ret = kread(genx_addr, &genx, 0x8);
  if (ret || !genx) {
    return 0;
  }
  uint64_t genx_10 = 0;
  ret = kread(genx + 0x10, &genx_10, 0x8);
  if (ret || !genx_10) {
    return 0;
  }
  uint64_t genx_10_10 = 0;
  ret = kread(genx_10 + 0x10, &genx_10_10, 0x8);
  if (ret) {
    return 0;
  }
  if (genx_10_10) {
    return genx_10_10;
  }
  uint64_t genx_10_0 = 0;
  ret = kread(genx_10, &genx_10_0, 0x8);
  if (ret || !genx_10_0) {
    return 0;
  }
  return genx_10_0;
}

/**
 * @brief           Test code to get magazine from current expert pointer
 */
__unused uint64_t expert_get_magazine(uint64_t gen_xprt) {
  if (!gen_xprt) {
    return 0;
  }
  int ret = 0;
  uint64_t mag_ptr = 0;
  ret = kread(gen_xprt + 0x10, &mag_ptr, 0x8);
  if (ret || !mag_ptr) {
    return 0;
  }
  uint64_t mag = 0;
  ret = kread(mag_ptr + 0x38, &mag, 0x8);
  if (ret || !mag) {
    return 0;
  }
  return mag;
}

/**
 * @brief           Test code to find the img4 nonce slot in a given magazine
 */
__unused uint64_t nonce_magazine_find_slot_img4(uint64_t mag) {
  uint64_t nonce_domain = 0xFFFFFFF006D0C830 + get_slide();
  if (!mag) {
    return 0;
  }
  int ret = 0;
  uint64_t off1 = 0;
  ret = kread(mag + 0x20, &off1, 8);
  if (ret || !off1) {
    return 0;
  }
  uint64_t off2 = 0;
  ret = kread(mag + 0x18, &off2, 8);
  if (ret || !off2) {
    return 0;
  }
  uint64_t tmp = off2;
  uint64_t tmp2 = 0;
  kread(tmp, &tmp2, 8);
  fprintf(stdout, "[+]: %s: off2: 0x%016llX\n", __FUNCTION__, off2);
  fprintf(stdout, "[+]: %s: tmp2: 0x%016llX\n", __FUNCTION__, tmp2);
  kread(tmp2, &tmp2, 8);
  fprintf(stdout, "[+]: %s: tmp2: 0x%016llX\n", __FUNCTION__, tmp2);
  kread(tmp2 + 0x40, &tmp2, 8);
  fprintf(stdout, "[+]: %s: tmp2: 0x%016llX\n", __FUNCTION__, tmp2);
  ret = kread(tmp, &tmp, 8);
  if (ret || !tmp) {
    return 0;
  }
  ret = kread(tmp, &tmp, 8);
  if (ret || !tmp) {
    return 0;
  }
  while (!kread(tmp, &tmp, 8) && tmp && !kread(tmp + 0x40, &tmp, 8) &&
         (tmp != nonce_domain)) {
    tmp += 8;
    if (!(off2 -= 1)) {
      return 0;
    }
  }
  ret = kread(off2, &tmp, 8);
  return ret ? 0 : tmp;
}

/**
 * @brief           Test code to print kernel slide
 */
int kernel_test(void) {
  x8A4_log_debug("slide: 0x%016llX\n", get_slide());
  return 0;
}
#endif

/**
 * @brief           Generates a new apnonce and generator via AppleMobileApNonce UserClient
 * @return          Zero on success
 */
/* Removed mutation API io_generate_apnonce: read-only research build. */


/**
 * @brief           Clears the apnonce and generator via AppleMobileApNonce UserClient
 * @return          Zero on success
 */
/* Removed mutation API io_clear_apnonce: read-only research build. */

