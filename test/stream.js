
var test = require("tap").test;
var crypto = require("crypto");
var n = require("../index").nacl;

test("stream", function(t) {
    // test vectors adapted from naclcrypto-20090310.pdf, chapter 8

    var nonceprefix = Buffer("69696ee955b62b73"+ "cd62bda875fc73d6", "hex");
    var noncesuffix = Buffer("8219e0036b7a0b37", "hex");
    var nonce = Buffer.concat([nonceprefix, noncesuffix]);
    var k1 = Buffer("1b27556473e985d4"+"62cd51197a9a46c7"+
                    "6009549eac6474f2"+"06c4ee0844f68389", "hex");
    var keystream = n.stream(4194304, nonce, k1);
    t.equal(keystream.length, 4194304);
    var h2 = crypto.createHash("sha256");
    h2.update(keystream, "binary");
    t.equal(h2.digest("hex"),
            "662b9d0e3463029156069b12f918691a98f7dfb2ca0393c96bbfc6b1fbd630a2");

    var zeromsg = Buffer(1000); zeromsg.fill(0);
    var stream1 = n.stream(1000, nonce, k1);
    var stream2 = n.stream_xor(zeromsg, nonce, k1);
    t.equivalent(stream1, stream2);
    var stream3 = n.stream_xor(stream2, nonce, k1);
    t.equivalent(stream3, zeromsg);

    t.throws(function() {n.stream(1234, nonce, k1, "extra");},
             {name: "Error", message: "Args: length, nonce, key"});
    t.throws(function() {n.stream("nope", nonce, k1);},
             {name: "TypeError", message: "arg[0] 'length' must be an Integer"});
    t.throws(function() {n.stream(1234, 0, k1);},
             {name: "TypeError", message: "arg[1] 'nonce' must be a Buffer"});
    t.throws(function() {n.stream(1234, nonce, 0);},
             {name: "TypeError", message: "arg[2] 'key' must be a Buffer"});

    var msg = Buffer("Hello world");
    t.throws(function() {n.stream_xor(msg, nonce, k1, "extra");},
             {name: "Error", message: "Args: message, nonce, key"});
    t.throws(function() {n.stream_xor(0, nonce, k1);},
             {name: "TypeError", message: "arg[0] 'message' must be a Buffer"});
    t.throws(function() {n.stream_xor(msg, 0, k1);},
             {name: "TypeError", message: "arg[1] 'nonce' must be a Buffer"});
    t.throws(function() {n.stream_xor(msg, nonce, 0);},
             {name: "TypeError", message: "arg[2] 'key' must be a Buffer"});

    t.end();
});
