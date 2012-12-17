#include <string>
using std::string;
#include "crypto_sign.h"

string crypto_sign_open(const string &sm_string, const string &pk_string)
{
  if (pk_string.size() != crypto_sign_PUBLICKEYBYTES) throw "incorrect public-key length";
  size_t smlen = sm_string.size();
  unsigned char m[smlen];
  unsigned long long mlen;
  if (crypto_sign_open(
        m,
        &mlen,
        (const unsigned char *) sm_string.c_str(),
        smlen,
        (const unsigned char *) pk_string.c_str()
        ) != 0)
    throw "ciphertext fails verification";
  return string(
    (char *) m,
    mlen
  );
}
