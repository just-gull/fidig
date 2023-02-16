#include <string.h>
#include <ctype.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/objects.h>

static void print_digest(const OBJ_NAME *name, void *arg) {
  /* Filter out signed digests (a.k.a signature algorithms) */
  if (strstr(name->name, "rsa") != NULL || strstr(name->name, "RSA") != NULL)
      return;
  if (!islower((unsigned char)*name->name))
      return;

  printf("  %s\n", name->name);
}

void print_digests() {
  printf("Supported digests:\n");
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
  OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_MD_METH, print_digest, NULL);
}

void calculate_digest(const char* digest_type, const char* file_path) {
  FILE* input_file = NULL;
  BIO *input = NULL;
  OSSL_LIB_CTX *library_context = NULL;
  int result = 0;
  const char * option_properties = NULL;
  EVP_MD *message_digest = NULL;
  EVP_MD_CTX *digest_context = NULL;
  unsigned int digest_length;
  unsigned char *digest_value = NULL;
  unsigned char buffer[512];
  int ii;
  
  input_file = fopen(file_path, "rb");
  if (input_file == NULL) {
    fprintf(stderr, "Can't open file '%s'!\n", file_path);
    return;
  }

  input = BIO_new_fd(fileno(input_file), 0);
  if (input == NULL) {
    fprintf(stderr, "BIO is NULL!\n");
    goto cleanup;
  }

  library_context = OSSL_LIB_CTX_new();
  if (library_context == NULL) {
      fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
      goto cleanup;
  }

  /*
    * Fetch a message digest by name
    * The algorithm name is case insensitive. 
    * See providers(7) for details about algorithm fetching
    */
  message_digest = EVP_MD_fetch(library_context, digest_type, option_properties);
  if (message_digest == NULL) {
      fprintf(stderr, "EVP_MD_fetch could not find %s.", digest_type);
      ERR_print_errors_fp(stderr);
      OSSL_LIB_CTX_free(library_context);
      return;
  }

  /* Determine the length of the fetched digest type */
  digest_length = EVP_MD_get_size(message_digest);
  if (digest_length <= 0) {
      fprintf(stderr, "EVP_MD_get_size returned invalid size.\n");
      goto cleanup;
  }

  digest_value = OPENSSL_malloc(digest_length);
  if (digest_value == NULL) {
      fprintf(stderr, "No memory.\n");
      goto cleanup;
  }

  /*
    * Make a message digest context to hold temporary state
    * during digest creation
    */
  digest_context = EVP_MD_CTX_new();
  if (digest_context == NULL) {
      fprintf(stderr, "EVP_MD_CTX_new failed.\n");
      ERR_print_errors_fp(stderr);
      goto cleanup;
  }

  /*
    * Initialize the message digest context to use the fetched 
    * digest provider
    */
  if (EVP_DigestInit(digest_context, message_digest) != 1) {
      fprintf(stderr, "EVP_DigestInit failed.\n");
      ERR_print_errors_fp(stderr);
      goto cleanup;
  }

  while ((ii = BIO_read(input, buffer, sizeof(buffer))) > 0) {
      if (EVP_DigestUpdate(digest_context, buffer, ii) != 1) {
          fprintf(stderr, "EVP_DigestUpdate() failed.\n");
          goto cleanup;
      }
  }

  if (EVP_DigestFinal(digest_context, digest_value, &digest_length) != 1) {
      fprintf(stderr, "EVP_DigestFinal() failed.\n");
      goto cleanup;
  }

  result = 1;
  fprintf(stdout, "%s (%s) = ", digest_type, file_path);
  for (ii=0; ii<digest_length; ii++) {
      fprintf(stdout, "%02x", digest_value[ii]);
  }
  fprintf(stdout, "\n");

cleanup:
  if (result != 1)
      ERR_print_errors_fp(stderr);
  /* OpenSSL free functions will ignore NULL arguments */
  EVP_MD_CTX_free(digest_context);
  OPENSSL_free(digest_value);
  EVP_MD_free(message_digest);

  OSSL_LIB_CTX_free(library_context);
  BIO_free(input);
  fclose(input_file);
}
