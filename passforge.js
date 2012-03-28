/*
 * passforge.js
 */

var passforge = passforge || {};

passforge.config = function(length, iterations, status_callback, result_callback) {
    passforge.length = length || 8;
    passforge.iterations = iterations || 1000;
    passforge.require_digits = false; // TODO (notimplemented)
    passforge.status_callback = status_callback;
    passforge.result_callback = result_callback;
}

/* A wrapper function to truncate the derived key to the correct length. */
passforge.apply_key_policy = function(key) {
    var b64key = sjcl.codec.base64url.fromBits(key);

    // truncate to desired length
    b64key = b64key.substring(0, passforge.length);

    if (passforge.require_digits) {
        console.log('require_digits not yet implemented');
        // TODO
    }
    return b64key;
}

passforge.pwgen = function(master, nickname, asynchronous) {
    // round up bytes required
    var bytes = Math.ceil(passforge.length * 3 / 4);

    master = sjcl.codec.utf8String.toBits(master);
    salt = sjcl.codec.utf8String.toBits(nickname);

    var start = new Date();

    if (asynchronous) {

        passforge.start = start;

        var result_handler = function(derivedKey) {
            var elapsed = (new Date() - passforge.start) / 1000;
            derivedKey = passforge.apply_key_policy(derivedKey);
            passforge.result_callback(derivedKey, elapsed);
        }

        if (!passforge.result_callback) {
            result_handler = null;
        }

        // derive key with PBKDF2 asynchronously
        var p = new sjcl.misc.pbkdf2async(master, salt, passforge.iterations,
                bytes * 8, sjcl.misc.hmac_sha1, passforge.status_callback,
                result_handler);
        return p.deriveKey();

    } else {
        // derive key with PBKDF2
        var derivedKey = sjcl.misc.pbkdf2(master, salt, passforge.iterations,
                                   bytes * 8, sjcl.misc.hmac_sha1);

        var elapsed = (new Date() - start) / 1000;

        derivedKey = passforge.apply_key_policy(derivedKey);
        result_callback && result_callback(derivedKey, elapsed);

        return [passforge.apply_key_policy(derivedKey), elapsed];
    }
};
