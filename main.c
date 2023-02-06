#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

static void print_usage() {
  printf("usage: fidig <digest-type> <path-to-a-file>\n");
  printf(" -h, --help - this message\n");
  printf(" -l, --list - lists available digests\n");
}

static void print_digest(const OBJ_NAME *name, void *arg) {
  /* Filter out signed digests (a.k.a signature algorithms) */
  if (strstr(name->name, "rsa") != NULL || strstr(name->name, "RSA") != NULL)
      return;
  if (!islower((unsigned char)*name->name))
      return;

  printf("  %s\n", name->name);
}

static void print_digests() {
  printf("Supported digests:\n");
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
  OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_MD_METH, print_digest, NULL);
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