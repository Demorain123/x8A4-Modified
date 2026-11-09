//
// Created by cryptic on 4/14/24.
//

/**
 * @file services.c
 * @author Cryptiiiic
 * @brief This file is for all ioservice related code.
 * @version 1.0.1
 * @date 2024-04-14
 *
 * @copyright Copyright (c) 2024
 */

/* Include headers */
#include <stdio.h>
#include <x8A4/Registry/registry.h>
#include <x8A4/Services/services.h>

/* Cached Variables */
io_service_t io_aes_accel_service_cached = IO_OBJECT_NULL;

/* Functions */
/**
 * @brief           Gets the IOAESAccelerator ioservice
 * @return          IOAESAccelerator ioservice
 */
io_service_t get_io_aes_accel_service(void) {
  if (io_aes_accel_service_cached != IO_OBJECT_NULL) {
    return io_aes_accel_service_cached;
  }
  io_service_t io_aes_accel_service = IOServiceGetMatchingService(
      kIOMasterPortDefault, IOServiceMatching("IOAESAccelerator"));
  if (io_aes_accel_service == IO_OBJECT_NULL) {
    fprintf(stderr, "[-]: %s: Failed to find ioservice IOAESAccelerator!\n",
            __FUNCTION__);
  }
  io_aes_accel_service_cached = io_aes_accel_service;
  return io_aes_accel_service;
}

/**
 * @brief           Gets the AppleMobileApNonce ioservice
 * @return          AppleMobileApNonce ioservice
 */
/* Removed mutation API get_apple_mobile_ap_nonce_service: read-only research build. */

