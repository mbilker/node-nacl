#include <v8.h>
#include <node.h>
#include <node_buffer.h>
#include <string>
#include <stdlib.h>
#include <unistd.h>
#include <crypto_box.h>
#include <crypto_sign.h>
#include <crypto_secretbox.h>
#include <crypto_onetimeauth.h>
#include <crypto_auth.h>
#include <crypto_stream.h>

using namespace std;
using namespace node;
using namespace v8;

static Handle<Value> node_crypto_box (const Arguments&);
static Handle<Value> node_crypto_box_open (const Arguments&);
static Handle<Value> node_crypto_box_keypair (const Arguments&);

static Handle<Value> node_crypto_sign (const Arguments&);
static Handle<Value> node_crypto_sign_open (const Arguments&);
static Handle<Value> node_crypto_sign_keypair (const Arguments&);

static Handle<Value> node_crypto_secretbox (const Arguments&);
static Handle<Value> node_crypto_secretbox_open (const Arguments&);

static Handle<Value> node_crypto_onetimeauth (const Arguments&);
static Handle<Value> node_crypto_onetimeauth_verify (const Arguments&);

static Handle<Value> node_crypto_auth (const Arguments&);
static Handle<Value> node_crypto_auth_verify (const Arguments&);

static Handle<Value> node_crypto_stream (const Arguments&);
static Handle<Value> node_crypto_stream_xor (const Arguments&);


#define LEAVE_VIA_EXCEPTION(msg) \
 return ThrowException(Exception::Error(String::New(msg)));

#define LEAVE_VIA_CUSTOM_EXCEPTION(errorFunc, msg)      \
  {  Local<Value> argv[] = {String::New(msg)};          \
  Local<Value> Err = (errorFunc)->NewInstance(1, argv); \
  return ThrowException(Err);  }

#define BAIL_IF_NOT_N_ARGS(nargs,msg) \
 if (args.Length() != nargs) \
   LEAVE_VIA_EXCEPTION(msg);

#define EXTRACT_BUFFER_ARG(arg, var, msg) \
  if (!Buffer::HasInstance(arg)) \
    return ThrowException(Exception::TypeError(String::New(msg " must be a Buffer"))); \
  string var = buf_to_str(arg->ToObject());

#define EXTRACT_INTEGER_ARG(arg, var, msg) \
  if (!arg->IsUint32())                      \
    return ThrowException(Exception::TypeError(String::New(msg " must be an Integer"))); \
  size_t var = arg->Uint32Value();

static string buf_to_str (Handle<Object> b) {
  return string(Buffer::Data(b), Buffer::Length(b));
}

static Buffer* str_to_buf (string s) {
  Buffer* res = Buffer::New(s.length());
  memcpy(Buffer::Data(res), s.c_str(), s.length());
  return res;
}

#define THROW_ERROR(msg) \
  ThrowException(Exception::Error(String::New(msg)))

static Handle<Value> node_crypto_box (const Arguments& args) {
  HandleScope scope;
  BAIL_IF_NOT_N_ARGS(4, "Args: message, nonce, pubkey, privkey");
  EXTRACT_BUFFER_ARG(args[0], m, "arg[0] 'message'");
  EXTRACT_BUFFER_ARG(args[1], n, "arg[1] 'nonce'");
  EXTRACT_BUFFER_ARG(args[2], pk, "arg[2] 'pubkey'");
  EXTRACT_BUFFER_ARG(args[3], sk, "arg[3] 'privkey'");
  try {
    string c = crypto_box(m,n,pk,sk);
    return scope.Close(str_to_buf(c)->handle_);
  } catch(char const *err) {
    return THROW_ERROR(err);
  }
}

static Handle<Value> node_crypto_box_open (const Arguments& args) {
  HandleScope scope;
  BAIL_IF_NOT_N_ARGS(4, "Args: ciphertext, nonce, pubkey, privkey");
  EXTRACT_BUFFER_ARG(args[0], c, "arg[0] 'ciphertext'");
  EXTRACT_BUFFER_ARG(args[1], n, "arg[1] 'nonce'");
  EXTRACT_BUFFER_ARG(args[2], pk, "arg[2] 'pubkey'");
  EXTRACT_BUFFER_ARG(args[3], sk, "arg[3] 'privkey'");
  try {
    string m = crypto_box_open(c,n,pk,sk);
    return scope.Close(str_to_buf(m)->handle_);
  } catch(char const *err) {
    return THROW_ERROR(err);
  }
}

static Handle<Value> node_crypto_box_keypair (const Arguments& args) {
  HandleScope scope;
  string sk;
  Buffer* pk_buf = str_to_buf(crypto_box_keypair(&sk));
  Buffer* sk_buf = str_to_buf(sk);
  Local<Array> res = Array::New(2);
  res->Set(0, pk_buf->handle_);
  res->Set(1, sk_buf->handle_);
  return scope.Close(res);
}


static Handle<Value> node_crypto_sign (const Arguments& args) {
  HandleScope scope;
  BAIL_IF_NOT_N_ARGS(2, "Args: message, signingkey");
  EXTRACT_BUFFER_ARG(args[0], m, "arg[0] 'message'");
  EXTRACT_BUFFER_ARG(args[1], sk, "arg[1] 'signingkey'");
  try {
    string sm = crypto_sign(m,sk);
    return scope.Close(str_to_buf(sm)->handle_);
  } catch(char const* err) {
    return THROW_ERROR(err);
  }
}

static Handle<Value> node_crypto_sign_open (const Arguments& args) {
  HandleScope scope;
  BAIL_IF_NOT_N_ARGS(2, "Args: signedmessage, verifyingkey");
  EXTRACT_BUFFER_ARG(args[0], sm, "arg[0] 'signedmessage'");
  EXTRACT_BUFFER_ARG(args[1], pk, "arg[1] 'verifyingkey'");
  try {
    string m = crypto_sign_open(sm,pk);
    return scope.Close(str_to_buf(m)->handle_);
  } catch(char const *err) {
    return THROW_ERROR(err);
  }
}

static Handle<Value> node_crypto_sign_keypair (const Arguments& args) {
  HandleScope scope;
  string sk;
  Buffer* pk_buf = str_to_buf(crypto_sign_keypair(&sk));
  Buffer* sk_buf = str_to_buf(sk);
  Local<Array> res = Array::New(2);
  res->Set(0, pk_buf->handle_);
  res->Set(1, sk_buf->handle_);
  return scope.Close(res);
}

static Handle<Value> node_crypto_sign_publickey (const Arguments& args) {
  HandleScope scope;
  BAIL_IF_NOT_N_ARGS(1, "Args: seed");
  EXTRACT_BUFFER_ARG(args[0], seed, "arg[0] 'seed'");
  string sk;
  Buffer* pk_buf = str_to_buf(crypto_sign_publickey(seed, &sk));
  Buffer* sk_buf = str_to_buf(sk);
  Local<Array> res = Array::New(2);
  res->Set(0, pk_buf->handle_);
  res->Set(1, sk_buf->handle_);
  return scope.Close(res);
}

static Handle<Value> node_crypto_secretbox (const Arguments& args) {
  HandleScope scope;
  BAIL_IF_NOT_N_ARGS(3, "Args: message, nonce, key");
  EXTRACT_BUFFER_ARG(args[0], m, "arg[0] 'message'");
  EXTRACT_BUFFER_ARG(args[1], n, "arg[1] 'nonce'");
  EXTRACT_BUFFER_ARG(args[2], k, "arg[2] 'key'");
  try {
    string c = crypto_secretbox(m,n,k);
    return scope.Close(str_to_buf(c)->handle_);
  } catch(char const *err) {
    return THROW_ERROR(err);
  }
}

static Handle<Value> node_crypto_secretbox_open (const Arguments& args) {
  HandleScope scope;
  BAIL_IF_NOT_N_ARGS(3, "Args: ciphertext, nonce, key");
  EXTRACT_BUFFER_ARG(args[0], c, "arg[0] 'ciphertext'");
  EXTRACT_BUFFER_ARG(args[1], n, "arg[1] 'nonce'");
  EXTRACT_BUFFER_ARG(args[2], k, "arg[2] 'key'");
  try {
    string m = crypto_secretbox_open(c,n,k);
    return scope.Close(str_to_buf(m)->handle_);
  } catch(char const *err) {
    return THROW_ERROR(err);
  }
}

static Handle<Value> node_crypto_onetimeauth (const Arguments& args) {
  HandleScope scope;
  BAIL_IF_NOT_N_ARGS(2, "Args: message, key");
  EXTRACT_BUFFER_ARG(args[0], m, "arg[0] 'message'");
  EXTRACT_BUFFER_ARG(args[1], k, "arg[1] 'key'");
  try {
    string a = crypto_onetimeauth(m,k);
    return scope.Close(str_to_buf(a)->handle_);
  } catch(char const *err) {
    return THROW_ERROR(err);
  }
}

static Handle<Value> node_crypto_onetimeauth_verify (const Arguments& args) {
  HandleScope scope;
  BAIL_IF_NOT_N_ARGS(3, "Args: authenticator, message, key");
  EXTRACT_BUFFER_ARG(args[0], a, "arg[0] 'authenticator'");
  EXTRACT_BUFFER_ARG(args[1], m, "arg[1] 'message'");
  EXTRACT_BUFFER_ARG(args[2], k, "arg[2] 'key'");
  try {
    crypto_onetimeauth_verify(a,m,k);
    return scope.Close(Null());
  } catch(char const *err) {
    return THROW_ERROR(err);
  }
}

static Handle<Value> node_crypto_auth (const Arguments& args) {
  HandleScope scope;
  BAIL_IF_NOT_N_ARGS(2, "Args: message, key");
  EXTRACT_BUFFER_ARG(args[0], m, "arg[0] 'message'");
  EXTRACT_BUFFER_ARG(args[1], k, "arg[1] 'key'");
  try {
    string a = crypto_auth(m,k);
    return scope.Close(str_to_buf(a)->handle_);
  } catch(char const *err) {
    return THROW_ERROR(err);
  }
}

static Handle<Value> node_crypto_auth_verify (const Arguments& args) {
  HandleScope scope;
  BAIL_IF_NOT_N_ARGS(3, "Args: authenticator, message, key");
  EXTRACT_BUFFER_ARG(args[0], a, "arg[0] 'authenticator'");
  EXTRACT_BUFFER_ARG(args[1], m, "arg[1] 'message'");
  EXTRACT_BUFFER_ARG(args[2], k, "arg[2] 'key'");
  try {
    crypto_auth_verify(a,m,k);
    return scope.Close(Null());
  } catch(char const *err) {
    return THROW_ERROR(err);
  }
}

static Handle<Value> node_crypto_stream (const Arguments& args) {
  HandleScope scope;
  BAIL_IF_NOT_N_ARGS(3, "Args: length, nonce, key");
  EXTRACT_INTEGER_ARG(args[0], clen, "arg[0] 'length'");
  EXTRACT_BUFFER_ARG(args[1], n, "arg[1] 'nonce'");
  EXTRACT_BUFFER_ARG(args[2], k, "arg[2] 'key'");
  try {
    string c = crypto_stream(clen,n,k);
    return scope.Close(str_to_buf(c)->handle_);
  } catch(char const *err) {
    return THROW_ERROR(err);
  }
}

static Handle<Value> node_crypto_stream_xor (const Arguments& args) {
  HandleScope scope;
  BAIL_IF_NOT_N_ARGS(3, "Args: message, nonce, key");
  EXTRACT_BUFFER_ARG(args[0], m, "arg[0] 'message'");
  EXTRACT_BUFFER_ARG(args[1], n, "arg[1] 'nonce'");
  EXTRACT_BUFFER_ARG(args[2], k, "arg[2] 'key'");
  try {
    string c = crypto_stream_xor(m,n,k);
    return scope.Close(str_to_buf(c)->handle_);
  } catch(char const *err) {
    return THROW_ERROR(err);
  }
}


extern "C" {
  void init (Handle<Object> target) {
    HandleScope scope;
    
    NODE_SET_METHOD(target, "box", node_crypto_box);
    NODE_SET_METHOD(target, "box_open", node_crypto_box_open);
    NODE_SET_METHOD(target, "box_keypair", node_crypto_box_keypair);
  
    NODE_SET_METHOD(target, "sign", node_crypto_sign);
    NODE_SET_METHOD(target, "sign_open", node_crypto_sign_open);
    NODE_SET_METHOD(target, "sign_keypair", node_crypto_sign_keypair);
    NODE_SET_METHOD(target, "sign_publickey", node_crypto_sign_publickey);

    NODE_SET_METHOD(target, "secretbox", node_crypto_secretbox);
    NODE_SET_METHOD(target, "secretbox_open", node_crypto_secretbox_open);

    NODE_SET_METHOD(target, "onetimeauth", node_crypto_onetimeauth);
    NODE_SET_METHOD(target, "onetimeauth_verify", node_crypto_onetimeauth_verify);

    NODE_SET_METHOD(target, "auth", node_crypto_auth);
    NODE_SET_METHOD(target, "auth_verify", node_crypto_auth_verify);

    NODE_SET_METHOD(target, "stream", node_crypto_stream);
    NODE_SET_METHOD(target, "stream_xor", node_crypto_stream_xor);
  
    target->Set(String::NewSymbol("box_NONCEBYTES"), Integer::New(crypto_box_NONCEBYTES));
    target->Set(String::NewSymbol("box_PUBLICKEYBYTES"), Integer::New(crypto_box_PUBLICKEYBYTES));
    target->Set(String::NewSymbol("box_SECRETKEYBYTES"), Integer::New(crypto_box_SECRETKEYBYTES));
  
    target->Set(String::NewSymbol("sign_PUBLICKEYBYTES"), Integer::New(crypto_sign_PUBLICKEYBYTES));
    target->Set(String::NewSymbol("sign_SECRETKEYBYTES"), Integer::New(crypto_sign_SECRETKEYBYTES));
  }
  NODE_MODULE(node_nacl, init)
}
