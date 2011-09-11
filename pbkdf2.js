/*
 * JavaScript implementation of Password-Based Key Derivation Function 2
 * (PBKDF2) as defined in RFC 2898, with tests from RFC 3962 and RFC 6070.
 *
 * Version 2.0
 * Copyright (c) 2011, Andy Brody
 * Add a synchronous mode, a test suite, and some cosmetic changes.
 *
 * Version 1.1
 * Copyright (c) 2007, Parvez Anandam
 * http://anandam.name/pbkdf2
 *
 * Distributed under the BSD license
 *
 * (Uses Paul Johnston's excellent SHA-1 JavaScript library sha1.js)
 * Thanks to Felix Gartsman for pointing out a bug in version 1.0
 */

/*
 * The module can be tested with pbkdf2_test.self_test(). (synchronous only)
 */

/*
 * The four arguments to the constructor of the PBKDF2 object are the password,
 * salt, number of iterations and number of bytes in the generated key. This
 * follows the RFC 2898 definition: PBKDF2 (P, S, c, dkLen)
 *
 * It also takes an optional argument iters_per_chunk, which determines the
 * number of iterations run before the status callback is triggered. If this
 * number is too low, it will slow down the computation. It defaults to 1/10 of
 * the number of iterations.
 *
 * The method deriveKey takes two parameters, both callback functions:
 * the first is used to provide status on the computation, the second
 * is called with the result of the computation (the generated key in hex).
 *
 * The method deriveKeySync operates synchronously. It takes no parameters and
 * returns the generated key in hex.
 *
 * Example of use:
 *
 *    <script src="sha1.js"></script>
 *    <script src="pbkdf2.js"></script>
 *    <script>
 *    var asynchronous = true;
 *    var mypbkdf2 = new PBKDF2("mypassword", "saltines", 1000, 16);
 *    var status_callback = function(percent_done) {
 *        percent_done = Math.round(percent_done);
 *        var text = "Computed " + percent_done + "%";
 *        document.getElementById("status").innerHTML = text;
 *    };
 *    var result_callback = function(key) {
 *        document.getElementById("status").innerHTML = "Derived key: " + key;
 *    };
 *
 *    if (asynchronous) {
 *        mypbkdf2.deriveKey(status_callback, result_callback);
 *    } else {
 *        result_callback(mypbkdf2.deriveKeySync());
 *    }
 *    </script>
 *    <div id="status"></div>
 *
 */

function PBKDF2(password, salt, num_iterations, num_bytes, options) {
	options = options || {};

    // Remember the password and salt
    var m_bpassword = rstr2binb(password);
    var m_salt = salt;

    // Total number of iterations
    var m_total_iterations = num_iterations;

    // Run iterations in chunks instead of all at once, so as to not block.
    // The size of chunk defaults to 1/10 of the iterations. This can be
    // adjusted for slower or faster machines as needed.
    var m_iterations_in_chunk = num_iterations / 10;
    if (options.iters_per_chunk) {
        m_iterations_in_chunk = options.iters_per_chunk;
    }

    // Iteration counter
    var m_iterations_done = 0;

    // Key length, as number of bytes
    var m_key_length = num_bytes;

    // The length (in bytes) of the output of the pseudo-random function.
    // Since HMAC-SHA1 is the standard, and what is used here, it's 20 bytes.
    var m_hash_length = 20;

    // Number of hash-sized blocks in the derived key (called 'l' in RFC2898)
    var m_total_blocks = Math.ceil(m_key_length/m_hash_length);

    // Start computation with the first block
    var m_current_block = 1;

    // Used in the HMAC-SHA1 computations
    var m_ipad = new Array(16);
    var m_opad = new Array(16);

    // This is where the result of the iterations gets stored
    var m_buffer = new Array(0x0,0x0,0x0,0x0,0x0);
    
    // The result
    var m_key = "";

    // Whether to run asynchronously
    var m_asynchronous = true;

    // The function to call with the result
    var m_result_func;

    // The function to call with status after computing every chunk
    var m_status_func;

    // Time at which deriveKey was started
    var m_start;

    // Total runtime in seconds
    var m_elapsed;

    // Set up the HMAC-SHA1 computations
    if (m_bpassword.length > 16) {
        m_bpassword = binb_sha1(m_bpassword, password.length * 8);
    }
    for (var i = 0; i < 16; i++) {
        m_ipad[i] = m_bpassword[i] ^ 0x36363636;
        m_opad[i] = m_bpassword[i] ^ 0x5C5C5C5C;
    }

    // Get the elapsed time in seconds
    this.getElapsed = function() {
        return m_elapsed;
    }

    // Starts the computation asynchronously
    this.deriveKey = function(status_callback, result_callback) {
        m_status_func = status_callback;
        m_result_func = result_callback;
        m_asynchronous = true;
        m_start = new Date();

        var this_object = this;
        setTimeout(function() { this_object.do_PBKDF2_chunk() }, 0);
    }

    // Synchronous computation
    this.deriveKeySync = function() {
        m_asynchronous = false;
        m_start = new Date();

        while (m_iterations_done < m_total_iterations
                || m_current_block < m_total_blocks) {
            this.do_PBKDF2_chunk();
        }
        return m_key;
    }


    // The workhorse
    this.do_PBKDF2_chunk = function() {
        var iterations = m_iterations_in_chunk;
        if (m_total_iterations - m_iterations_done < m_iterations_in_chunk)
            iterations = m_total_iterations - m_iterations_done;
            
        for (var i=0; i<iterations; i++) {
            // compute HMAC-SHA1
            if (m_iterations_done == 0) {
                var salt_block = m_salt +
                        String.fromCharCode(m_current_block >> 24 & 0xF) +
                        String.fromCharCode(m_current_block >> 16 & 0xF) +
                        String.fromCharCode(m_current_block >>  8 & 0xF) +
                        String.fromCharCode(m_current_block       & 0xF);

                m_hash = binb_sha1(m_ipad.concat(rstr2binb(salt_block)),
                                   512 + salt_block.length * 8);
                m_hash = binb_sha1(m_opad.concat(m_hash), 512 + 160);
            } else {
                m_hash = binb_sha1(m_ipad.concat(m_hash),
                                   512 + m_hash.length * 32);
                m_hash = binb_sha1(m_opad.concat(m_hash), 512 + 160);
            }

            for (var j=0; j<m_hash.length; ++j)
                    m_buffer[j] ^= m_hash[j];

            m_iterations_done++;
        }

        // Call the status callback function
        if (m_asynchronous) {
            m_status_func((m_current_block - 1 +
                    m_iterations_done/m_total_iterations)
                    / m_total_blocks * 100);
        }

        if (m_iterations_done < m_total_iterations) {
            // Continue with another chunk
            if (m_asynchronous) {
                var this_object = this;
                setTimeout(function() { this_object.do_PBKDF2_chunk() }, 0);
            } else {
                return;
            }
        } else {
            if (m_current_block < m_total_blocks) {
                // Compute the next block (T_i in RFC 2898)
                
                m_key += binb2hex(m_buffer);
            
                m_current_block++;
                m_buffer = new Array(0x0,0x0,0x0,0x0,0x0);
                m_iterations_done = 0;

                if (m_asynchronous) {
                    var this_object = this;
                    setTimeout(function(){ this_object.do_PBKDF2_chunk() }, 0);
                } else {
                    return;
                }
            } else {
                // We've computed the final block T_l; we're done.
            
                var tmp = binb2hex(m_buffer);
                m_key += tmp.substr(0, (m_key_length -
                                (m_total_blocks - 1) * m_hash_length) * 2 );
                
                m_elapsed = (new Date() - m_start) / 1000;

                // Call the result callback function
                m_result_func(m_key, m_elapsed);

                // Return the key in case anyone is waiting on the value
                return m_key;
            }
        }
    }
}

/*
 * Convert an array of big-endian words to a hex string.
 * (present in old versions of sha1.js)
 */
function binb2hex(binarray) {
    return rstr2hex(binb2rstr(binarray));
}


var pbkdf2_test = pbkdf2_test || {};

/*
 * Test vectors from RFC 6070
 */
pbkdf2_test.vectors_rfc6070 = new Array(
    ["password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"],
    ["password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"],
    ["password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"],
    ["passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
     25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"],
    ["pass\0word", "sa\0lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"]
);

/*
 * Include this vector if you have time to kill.
 */
pbkdf2_test.vectors_rfc6070_extra = new Array(
    ["password", "salt", 16777216, 20,
     "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"]
);

/*
 * Test vectors from RFC 3962
 */
pbkdf2_test.vectors_rfc3962 = new Array(
    ["password", "ATHENA.MIT.EDUraeburn", 1, 16,
     "cdedb5281bb2f801565a1122b2563515"],
    ["password", "ATHENA.MIT.EDUraeburn", 1, 32,
     "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837"],
    ["password", "ATHENA.MIT.EDUraeburn", 2, 16,
     "01dbee7f4a9e243e988b62c73cda935d"],
    ["password", "ATHENA.MIT.EDUraeburn", 2, 32,
     "01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86"],
    ["password", "ATHENA.MIT.EDUraeburn", 1200, 16,
     "5c08eb61fdf71e4e4ec3cf6ba1f5512b"],
    ["password", "ATHENA.MIT.EDUraeburn", 1200, 32,
     "5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13"],

    ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
     "pass phrase equals block size", 1200, 16,
     "139c30c0966bc32ba55fdbf212530ac9"],
    ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
     "pass phrase equals block size", 1200, 32,
     "139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1"],
    ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
     "pass phrase exceeds block size", 1200, 16,
     "9ccad6d468770cd51b10e6a68721be61"],
    ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
     "pass phrase exceeds block size", 1200, 32,
     "9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a"],

    ["\xf0\x9d\x84\x9e", "EXAMPLE.COMpianist", 50, 16,
     "6b9cf26d45455a43a5b8bb276a403b39"],
    ["\xf0\x9d\x84\x9e", "EXAMPLE.COMpianist", 50, 32,
     "6b9cf26d45455a43a5b8bb276a403b39e7fe37a0c41e02c281ff3069e1e94f52"]
);

/*
 * Run a round of self tests on a list of vectors.
 */
pbkdf2_test.do_test = function(vectors) {
    var v;
    var derived;
    var succeeded = 0;
    for (var i = 0; i < vectors.length; i++) {
        v = vectors[i];
        console.log(v);
        var mypbkdf2 = new PBKDF2(v[0], v[1], v[2], v[3]);
        derived = mypbkdf2.deriveKeySync();
        if (derived === v[4]) {
            console.log("PASS in " + mypbkdf2.getElapsed() + "s");
            succeeded++;
        } else {
            console.log("!! FAIL: got " + derived);
        }
    }

    console.log(succeeded + " of " + vectors.length + " tests succeeded.");
    return (succeeded == vectors.length);
};


/*
 * Test the correctness of the PBKDF2 module with a series of vectors.
 * The vectors are specified by RFC 6070 and RFC 3962.
 * Tests that may take a long time are not run unless include_extra is True.
 */
pbkdf2_test.self_test = function(include_extra) {
    var result = this.do_test(this.vectors_rfc6070);

    result = result && this.do_test(this.vectors_rfc3962);

    if (include_extra) {
        console.log("This test will take ~9 minutes on a 6000 BogoMips CPU.");
        result = result && this.do_test(this.vectors_rfc6070_extra);
    }

    if (result) {
        console.log("All tests succeeded.");
    } else {
        console.log("SOME TESTS FAILED.");
    }

    return result;
};

