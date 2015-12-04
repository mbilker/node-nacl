//include node_buffer.h
#include <nan.h>

#include <string>
#include <stdlib.h>
#include <unistd.h>

#include <crypto_box.h>
#include <crypto_sign.h>
#include <crypto_secretbox.h>
#include <crypto_onetimeauth.h>
#include <crypto_stream.h>

using namespace std;

NAN_METHOD(box);
NAN_METHOD(box_open);
NAN_METHOD(box_keypair);

NAN_METHOD(sign);
NAN_METHOD(sign_open);
NAN_METHOD(sig_keypairn);

NAN_METHOD(secretbox);
NAN_METHOD(secretbox_open);

NAN_METHOD(onetimeauth);
NAN_METHOD(onetimeauth_verify);

NAN_METHOD(stream);
NAN_METHOD(stream_xor);

static string buf_to_str(v8::Local<v8::Object> b) {
  return string(node::Buffer::Data(b), node::Buffer::Length(b));
}

static v8::Local<v8::Object> str_to_buf(string s) {
  v8::Local<v8::Object> res = Nan::NewBuffer(s.length()).ToLocalChecked();
  memcpy(node::Buffer::Data(res), s.c_str(), s.length());
  return res;
}

#define THROW_ERROR(msg) \
  Nan::ThrowError(msg)

NAN_METHOD(box) {
  string m = buf_to_str(info[0]->ToObject());
  string n = buf_to_str(info[1]->ToObject());
  string pk = buf_to_str(info[2]->ToObject());
  string sk = buf_to_str(info[3]->ToObject());
  try {
    string c = crypto_box(m,n,pk,sk);
    info.GetReturnValue().Set(str_to_buf(c));
  } catch(char const *err) {
    THROW_ERROR(err);
  }
}

NAN_METHOD(box_open) {
  string c = buf_to_str(info[0]->ToObject());
  string n = buf_to_str(info[1]->ToObject());
  string pk = buf_to_str(info[2]->ToObject());
  string sk = buf_to_str(info[3]->ToObject());
  try {
    string m = crypto_box_open(c,n,pk,sk);
    info.GetReturnValue().Set(str_to_buf(m));
  } catch(char const *err) {
    return THROW_ERROR(err);
  }
}

NAN_METHOD(box_keypair) {
  string sk;
  v8::Local<v8::Object> pk_buf = str_to_buf(crypto_box_keypair(&sk));
  v8::Local<v8::Object> sk_buf = str_to_buf(sk);
  v8::Local<v8::Array> res = Nan::New<v8::Array>(2);
  res->Set(0, pk_buf);
  res->Set(1, sk_buf);
  info.GetReturnValue().Set(res);
}


NAN_METHOD(sign) {
  string m = buf_to_str(info[0]->ToObject());
  string sk = buf_to_str(info[1]->ToObject());
  try {
    string sm = crypto_sign(m,sk);
    info.GetReturnValue().Set(str_to_buf(sm));
  } catch(char const* err) {
    THROW_ERROR(err);
  }
}

NAN_METHOD(sign_open) {
  string sm = buf_to_str(info[0]->ToObject());
  string pk = buf_to_str(info[1]->ToObject());
  try {
    string m = crypto_sign_open(sm,pk);
    info.GetReturnValue().Set(str_to_buf(m));
  } catch(char const *err) {
    THROW_ERROR(err);
  }
}

NAN_METHOD(sign_keypair) {
  string sk;
  v8::Local<v8::Object> pk_buf = str_to_buf(crypto_sign_keypair(&sk));
  v8::Local<v8::Object> sk_buf = str_to_buf(sk);
  v8::Local<v8::Array> res = Nan::New<v8::Array>(2);
  res->Set(0, pk_buf);
  res->Set(1, sk_buf);
  info.GetReturnValue().Set(res);
}

NAN_METHOD(secretbox) {
  string m = buf_to_str(info[0]->ToObject());
  string n = buf_to_str(info[1]->ToObject());
  string k = buf_to_str(info[2]->ToObject());
  try {
    string c = crypto_secretbox(m,n,k);
    info.GetReturnValue().Set(str_to_buf(c));
  } catch(char const *err) {
    THROW_ERROR(err);
  }
}

NAN_METHOD(secretbox_open) {
  string c = buf_to_str(info[0]->ToObject());
  string n = buf_to_str(info[1]->ToObject());
  string k = buf_to_str(info[2]->ToObject());
  try {
    string m = crypto_secretbox_open(c,n,k);
    info.GetReturnValue().Set(str_to_buf(m));
  } catch(char const *err) {
    THROW_ERROR(err);
  }
}

NAN_METHOD(onetimeauth) {
  string m = buf_to_str(info[0]->ToObject());
  string k = buf_to_str(info[1]->ToObject());
  try {
    string a = crypto_onetimeauth(m,k);
    info.GetReturnValue().Set(str_to_buf(a));
  } catch(char const *err) {
    THROW_ERROR(err);
  }
}

NAN_METHOD(onetimeauth_verify) {
  string a = buf_to_str(info[0]->ToObject());
  string m = buf_to_str(info[1]->ToObject());
  string k = buf_to_str(info[2]->ToObject());
  try {
    crypto_onetimeauth_verify(a,m,k);
    info.GetReturnValue().SetNull();
  } catch(char const *err) {
    THROW_ERROR(err);
  }
}

NAN_METHOD(stream) {
  size_t clen = info[0]->IntegerValue();
  string n = buf_to_str(info[1]->ToObject());
  string k = buf_to_str(info[2]->ToObject());
  try {
    string c = crypto_stream(clen,n,k);
    info.GetReturnValue().Set(str_to_buf(c));
  } catch(char const *err) {
    THROW_ERROR(err);
  }
}

NAN_METHOD(stream_xor) {
  string m = buf_to_str(info[0]->ToObject());
  string n = buf_to_str(info[1]->ToObject());
  string k = buf_to_str(info[2]->ToObject());
  try {
    string c = crypto_stream_xor(m,n,k);
    info.GetReturnValue().Set(str_to_buf(c));
  } catch(char const *err) {
    THROW_ERROR(err);
  }
}

NAN_MODULE_INIT(InitAll) {
  Nan::Set(target, Nan::New("box").ToLocalChecked(), Nan::GetFunction(Nan::New<v8::FunctionTemplate>(box)).ToLocalChecked());
  Nan::Set(target, Nan::New("box_open").ToLocalChecked(), Nan::GetFunction(Nan::New<v8::FunctionTemplate>(box_open)).ToLocalChecked());
  Nan::Set(target, Nan::New("box_keypair").ToLocalChecked(), Nan::GetFunction(Nan::New<v8::FunctionTemplate>(box_keypair)).ToLocalChecked());

  Nan::Set(target, Nan::New("sign").ToLocalChecked(), Nan::GetFunction(Nan::New<v8::FunctionTemplate>(sign)).ToLocalChecked());
  Nan::Set(target, Nan::New("sign_open").ToLocalChecked(), Nan::GetFunction(Nan::New<v8::FunctionTemplate>(sign_open)).ToLocalChecked());
  Nan::Set(target, Nan::New("sign_keypair").ToLocalChecked(), Nan::GetFunction(Nan::New<v8::FunctionTemplate>(sign_keypair)).ToLocalChecked());

  Nan::Set(target, Nan::New("secretbox").ToLocalChecked(), Nan::GetFunction(Nan::New<v8::FunctionTemplate>(secretbox)).ToLocalChecked());
  Nan::Set(target, Nan::New("secretbox_open").ToLocalChecked(), Nan::GetFunction(Nan::New<v8::FunctionTemplate>(secretbox_open)).ToLocalChecked());

  Nan::Set(target, Nan::New("onetimeauth").ToLocalChecked(), Nan::GetFunction(Nan::New<v8::FunctionTemplate>(onetimeauth)).ToLocalChecked());
  Nan::Set(target, Nan::New("onetimeauth_verify").ToLocalChecked(), Nan::GetFunction(Nan::New<v8::FunctionTemplate>(onetimeauth_verify)).ToLocalChecked());

  Nan::Set(target, Nan::New("stream").ToLocalChecked(), Nan::GetFunction(Nan::New<v8::FunctionTemplate>(stream)).ToLocalChecked());
  Nan::Set(target, Nan::New("stream_xor").ToLocalChecked(), Nan::GetFunction(Nan::New<v8::FunctionTemplate>(stream_xor)).ToLocalChecked());

  Nan::Set(target, Nan::New("box_NONCEBYTES").ToLocalChecked(), Nan::New<v8::Integer>(crypto_box_NONCEBYTES));
  Nan::Set(target, Nan::New("box_PUBLICKEYBYTES").ToLocalChecked(), Nan::New<v8::Integer>(crypto_box_PUBLICKEYBYTES));
  Nan::Set(target, Nan::New("box_SECRETKEYBYTES").ToLocalChecked(), Nan::New<v8::Integer>(crypto_box_SECRETKEYBYTES));

  Nan::Set(target, Nan::New("sign_PUBLICKEYBYTES").ToLocalChecked(), Nan::New<v8::Integer>(crypto_sign_PUBLICKEYBYTES));
  Nan::Set(target, Nan::New("sign_SECRETKEYBYTES").ToLocalChecked(), Nan::New<v8::Integer>(crypto_sign_SECRETKEYBYTES));
}

NODE_MODULE(nacl, InitAll)
