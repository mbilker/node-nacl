
var test = require("tap").test;
var crypto = require("crypto"); // for raw SHA512, until we get it from nacl
var n = require("../index").nacl;
function fromHex(hex) { return Buffer(hex, "hex"); }
function padKey(hex) {
    // hmac is specified to pad or hash
    var key = Buffer(hex, "hex");
    if (key.length < 32) {
        var pad = Buffer(32-key.length); pad.fill(0);
        var padded = Buffer.concat([key, pad]);
        return padded;
    }
    if (key.length > 32) {
        throw new Error("nacl_auth_sha512256() cannot compute these keys");
    }
    return key;
}

test("auth", function(t) {
    // test vectors from RFC 4321. However, nacl_auth_sha512256 (meaning
    // HMAC-SHA512 with the output truncated down to 256 bits) only
    // implements key.length=32, so the HMAC-SHA512 is always zero-padded out
    // to 128 bytes. Thus the domain of nacl_auth_sha512256 is does not
    // include any test vector with a key longer than 32 bytes, so we skip
    // those tests.
    t.equivalent(n.auth(Buffer("Hi There"), 
                        padKey("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")),
                 fromHex("87aa7cdea5ef619d4ff0b4241a1d6cb0"+
                         "2379f4e2ce4ec2787ad0b30545e17cde"),
                "Test Case 1");
    t.equivalent(n.auth(Buffer("what do ya want for nothing?"),
                        padKey("4a656665")),
                 fromHex("164b7a7bfcf819e2e395fbe73b56e0a3"+
                         "87bd64222e831fd610270cd7ea250554"),
                 "Test Case 2");
    t.equivalent(n.auth(fromHex("dddddddddddddddddddddddddddddddd"+
                                "dddddddddddddddddddddddddddddddd"+
                                "dddddddddddddddddddddddddddddddd"+
                                "dddd"),
                        padKey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
                 fromHex("fa73b0089d56a284efb0f0756c890be9"+
                         "b1b5dbdd8ee81a3655f83e33b2279d39"),
                 "Test Case 3");
    t.equivalent(n.auth(fromHex("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"+
                                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"+
                                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"+
                                "cdcd"),
                        padKey("0102030405060708090a0b0c0d0e0f10"+
                               "111213141516171819")),
                 fromHex("b0ba465637458c6990e5a8c5f61d4af7"+
                         "e576d97ff94b872de76f8050361ee3db"),
                 "Test Case 4");
    t.equivalent(n.auth(Buffer("Test With Truncation"),
                        padKey("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"+
                               "0c0c0c0c")).slice(0, 16),
                 fromHex("415fad6271580a531d4179bc891d87a6"),
                 "Test Case 5");
    /*
    t.equivalent(n.auth(Buffer("Test Using Larger Than Block-Size Key - Hash Key First"),
                        padKey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaa")),
                 fromHex("80b24263c7c1a3ebb71493c1dd7be8b4"+
                         "9b46d1f41b4aeec1121b013783f8f352"),
                 "Test Case 6");
    t.equivalent(n.auth(Buffer("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being useed by the HMAC algorithm."),
                        padKey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
                               "aaaaaa")),
                 fromHex("e37b6a775dc87dbaa4dfa9f96e5e3ffd"+
                         "debd71f8867289865df5a32d20cdc944"),
                 "Test Case 7");
     */
    t.end();
});
