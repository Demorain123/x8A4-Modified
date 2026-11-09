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
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

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
  /*
   * A research-only, M1-specific fail-closed gate: reject wrong models or
   * kernels before invoking libkrw. This is NOT proof that offsets are right.
   */
  char model[64] = {0};
  char osrelease[64] = {0};
  char build[64] = {0};
  size_t size = sizeof(model);
  if (geteuid() != 0 ||
      sysctlbyname("hw.machine", model, &size, NULL, 0) != 0 ||
      size == 0 || size > sizeof(model) || model[size - 1] != '\0' ||
      strcmp(model, "iPad13,4") != 0) {
    fputs("STOP: root and iPad13,4 required for this research build.\n", stderr);
    return 1;
  }
  size = sizeof(osrelease);
  if (sysctlbyname("kern.osrelease", osrelease, &size, NULL, 0) != 0 ||
      size == 0 || size > sizeof(osrelease) || osrelease[size - 1] != '\0' ||
      strcmp(osrelease, "23.3.0") != 0) {
    fputs("STOP: expected Darwin 23.3.0; no reads.\n", stderr);
    return 1;
  }
  size = sizeof(build);
  if (sysctlbyname("kern.osversion", build, &size, NULL, 0) != 0 ||
      size == 0 || size > sizeof(build) || build[size - 1] != '\0' ||
      strcmp(build, "21D61") != 0) {
    fputs("STOP: expected exact iPadOS build 21D61; no reads.\n", stderr);
    return 1;
  }
  if (x8A4_init() != 0) {
    fputs("STOP: kernel access initialization failed.\n", stderr);
    return 1;
  }
  return x8A4_cli_get_accel_keys(requested) == 0 ? 0 : 1;
#endif
}
