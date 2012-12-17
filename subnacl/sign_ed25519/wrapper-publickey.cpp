#include <string>
using std::string;
#include "crypto_sign.h"

string crypto_sign_publickey(const string &seed_string, string *sk_string)
{
  if (seed_string.size() != 32) throw "incorrect seed length";
  unsigned char seed[32];
  for (int i = 0;i < 32;++i) seed[i] = seed_string[i];
  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
  crypto_sign_publickey(seed,pk,sk);
  *sk_string = string((char *) sk,sizeof sk);
  return string((char *) pk,sizeof pk);
}
