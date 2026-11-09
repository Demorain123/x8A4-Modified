/*
 * x8A4-Modified: one-shot, target-only record archive CLI.
 *
 * The installed iPad x8A4 is untouched. This program has no mutation
 * commands, and live kernel reads remain disabled by default.
 */
#include <x8A4/x8A4.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

static void help(const char *name) {
  printf("Usage: %s --help | --export-accel-records NEW_PRIVATE_DIRECTORY\n", name);
  puts("The directory must not exist; the program creates it with mode 0700.");
  puts("Only raw 52-byte records for IDs 0x8A3 and 0x8A4 are written.");
  puts("Safety build: live kernel key reads are DISABLED by default.");
}

int main(int argc, char **argv) {
  static const struct option options[] = {
    {"help", no_argument, NULL, 'h'},
    {"export-accel-records", required_argument, NULL, 'e'},
    {NULL, 0, NULL, 0}
  };
  int opt;
  const char *output_dir = NULL;
  while ((opt = getopt_long(argc, argv, "he:", options, NULL)) != -1) {
    if (opt == 'h') { help(argv[0]); return 0; }
    if (opt != 'e' || output_dir) { help(argv[0]); return 2; }
    if (!optarg || !*optarg) {
      fputs("A new private output directory is required.\n", stderr);
      return 2;
    }
    output_dir = optarg;
  }
  if (!output_dir || optind != argc) { help(argv[0]); return 2; }

#if !defined(X8A4_ENABLE_LIVE_KEY_READ) || !(X8A4_ENABLE_LIVE_KEY_READ)
  (void)output_dir;
  fputs("STOP: live kernel key reading disabled in this safety build.\n", stderr);
  return 78;
#else
  umask(077);
  char model[64] = {0};
  char osrelease[64] = {0};
  char build[64] = {0};
  size_t size = sizeof(model);
  if (geteuid() != 0 ||
      sysctlbyname("hw.machine", model, &size, NULL, 0) != 0 ||
      size == 0 || size > sizeof(model) || model[size - 1] != '\0' ||
      strcmp(model, "iPad13,4") != 0) {
    fputs("STOP: root and iPad13,4 required; no reads.\n", stderr);
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
  return x8A4_cli_export_target_records(output_dir);
#endif
}
