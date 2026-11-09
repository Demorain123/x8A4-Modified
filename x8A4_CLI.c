/*
 * x8A4-Modified: restricted experimental CLI.
 *
 * The installed iPad x8A4 is untouched. This program exposes no mutation
 * commands, and live kernel key reads are disabled by default pending audit.
 */
#include <x8A4/x8A4.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void help(const char *name) {
  printf("Usage: %s --help | --get-accel-key 0x8A3|0x8A4\n", name);
  puts("Safety build: live kernel key reads are DISABLED by default.");
}

int main(int argc, char **argv) {
  static const struct option options[] = {
    {"help", no_argument, NULL, 'h'},
    {"get-accel-key", required_argument, NULL, 'k'},
    {NULL, 0, NULL, 0}
  };
  int opt;
  uint32_t requested = 0;
  while ((opt = getopt_long(argc, argv, "hk:", options, NULL)) != -1) {
    if (opt == 'h') { help(argv[0]); return 0; }
    if (opt != 'k') { help(argv[0]); return 2; }
    if (requested) {
      fputs("Only one key request per invocation is supported.\n", stderr);
      return 2;
    }
    errno = 0;
    char *end = NULL;
    unsigned long val = strtoul(optarg, &end, 0);
    if (errno || end == optarg || *end ||
        (val != 0x8A3 && val != 0x8A4)) {
      fputs("Only explicit key IDs 0x8A3 and 0x8A4 are allowed.\n", stderr);
      return 2;
    }
    requested = (uint32_t)val;
  }
  if (!requested || optind != argc) { help(argv[0]); return 2; }

#if !defined(X8A4_ENABLE_LIVE_KEY_READ) || !(X8A4_ENABLE_LIVE_KEY_READ)
  (void)requested;
  fputs("STOP: live kernel key reading disabled in this safety build.\n", stderr);
  return 78;
#else
  if (x8A4_init() != 0) {
    fputs("STOP: kernel access initialization failed.\n", stderr);
    return 1;
  }
  x8A4_cli_get_accel_keys(requested);
  /* A success exit alone is not evidence of a valid device-specific key. */
  return 0;
#endif
}
