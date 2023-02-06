#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

static void print_usage() {
  printf("usage: fidig <digest-type> <path-to-a-file>\n");
  printf(" -h, --help - this message\n");
  printf(" -l, --list - lists available digests\n");
}

static void print_digests() {
  printf("Supported digests: ...\n");
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

  OSSL_LIB_CTX *openssl_context;
  openssl_context = OSSL_LIB_CTX_new();
  if (openssl_context == NULL) {
    fprintf(stderr, "OpenSSL context is NULL!\n");
    goto cleanup;
  }

cleanup:
  OSSL_LIB_CTX_free(openssl_context);
  
  return EXIT_SUCCESS;
}