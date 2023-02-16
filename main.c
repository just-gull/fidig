#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "util.h"

static void print_usage() {
  printf("usage: fidig <digest-type> <path-to-a-file>\n");
  printf(" -h, --help - this message\n");
  printf(" -l, --list - lists available digests\n");
}

int main(int argc, char* argv[]) {
  if (!(argc == 2 || argc == 3)) {
    print_usage();
    return EXIT_SUCCESS;
  } else if (argc == 2) {
    if (strncmp(argv[1], "-l", 3) == 0 || strncmp(argv[1], "--list", 7) == 0) {
      print_digests();
      return EXIT_SUCCESS;
    } else {
      print_usage();
      return EXIT_SUCCESS;
    }
  }

  calculate_digest(argv[1], argv[2]);
  
  return EXIT_SUCCESS;
}