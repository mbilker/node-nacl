
var test = require("tap").test;
var fs = require("fs");

var nacl = require("../index").nacl;
var run_only_line = null;

function one_test_line(t, line, lineno) {
    if (!line.length)
        return;
    if (run_only_line && lineno != run_only_line)
        return;
    var x = line.split(":");
    var A = Buffer(x[0], "hex"); // private signing key (seed+pubkey)
    var B = Buffer(x[1], "hex"); // public verifying key
    var C = Buffer(x[2], "hex"); // message
    var D = Buffer(x[3], "hex"); // sigmsg
    // A[:32] is the 32 byte seed (the entropy input to H())
    // A[32:] == B == the public point (pubkey)
    // C is the message
    // D is 64 bytes of signature (R+S) prepended to the message

    var sk = A;
    var vk = B;
    var msg = C;
    var sigmsg = D;
    // note that R depends only upon the second half of H(seed). S
    // depends upon both the first half (the exponent) and the second
    // half

    var newkeys = nacl.sign_publickey(sk.slice(0,32));
    t.equivalent(newkeys[0], vk, "regenerate verfkey from seed line="+lineno);
    t.equivalent(newkeys[1], sk, "regenerate signkey from seed line="+lineno);

    var newsigmsg = nacl.sign(msg, sk);
    t.equivalent(newsigmsg, sigmsg, "deterministic signatures line="+lineno);
    var newmsg = nacl.sign_open(sigmsg, vk); // no exception
    t.equivalent(newmsg, msg, "sign_open returns message line="+lineno);
}

var katfile = module.filename.slice(0, module.filename.lastIndexOf("/")) + "/" + "kat-ed25519.txt";

test("sign-KAT", function(t) {
         // kat-ed25519.txt comes from "sign.input" on ed25519.cr.yp.to . The
         // pure-python ed25519.py in the same distribution uses a very
         // different key format than the one used by NaCl.
         var kat_data = fs.readFileSync(katfile).toString();
         var lines = kat_data.trim().split("\n");
         t.plan(4*lines.length);
         lines.forEach(function(line, lineno0) {
                           one_test_line(t,line, lineno0+1);
                       });
         t.end();
});

test("sign", function(t) {
    var newkeys = nacl.sign_keypair();
    var vk = newkeys[0];
    var sk = newkeys[1];
    var msg = Buffer("Hello World");
    var sigmsg = nacl.sign(msg, sk);
    nacl.sign_open(sigmsg, vk);
    t.throws(function() {nacl.sign_open(Buffer.concat([Buffer([0]), sigmsg]),
                                        vk);},
             {name: "Error", message: "ciphertext fails verification"});

    t.throws(function() {nacl.sign(msg, sk, "extra");},
             {name: "Error", message: "Args: message, signingkey"});
    t.throws(function() {nacl.sign(0, sk);},
             {name: "TypeError", message: "arg[0] 'message' must be a Buffer"});
    t.throws(function() {nacl.sign(msg, 0);},
             {name: "TypeError", message: "arg[1] 'signingkey' must be a Buffer"});

    t.throws(function() {nacl.sign_open(sigmsg, vk, "extra");},
             {name: "Error", message: "Args: signedmessage, verifyingkey"});
    t.throws(function() {nacl.sign_open(0, vk);},
             {name: "TypeError", message: "arg[0] 'signedmessage' must be a Buffer"});
    t.throws(function() {nacl.sign_open(sigmsg, 0);},
             {name: "TypeError", message: "arg[1] 'verifyingkey' must be a Buffer"});

    t.end();
});
