/*
 * passforge.js
 *
 * Javascript implementation of PassForge
 *
 * Andy Brody
 * 2012
 *
 */

var passforge = passforge || {};

passforge.SALT_LENGTH = 16;

passforge.LEVEL_MAP = {'very low': 12,
                       'low': 13,
                       'medium': 14,
                       'high': 15,
                       'very high': 16};

passforge.DEBUG = false;

passforge.result_callback = null;
passforge.status_callback = null;

passforge.config = function(result_callback, status_callback) {
    passforge.result_callback = result_callback;
    passforge.status_callback = status_callback;
}

/*
 * Create a suitable salt from the user-supplied nickname.
 *
 * We are using truncated SHA1, but note that the cryptographic properties of
 * this function are actually not important. All we care about is that the
 * output length be SALT_LENGTH and that the output be unlikely to collide with
 * other commonly used nicknames.
 */
passforge.salt_from_nickname = function(nick) {
    if (typeof(Sha1) == 'undefined') {
        throw "Could not find 'Sha1'. Did you include sha1.js?";
    }
    digest = Sha1.hash(nick);
    if (digest.length < passforge.SALT_LENGTH) {
        throw "AssertionError: digest.length was less than SALT_LENGTH";
    }
    return digest.substr(0, passforge.SALT_LENGTH);
}

passforge.generate = function(password, nickname, log_rounds, length) {
    if (typeof(bCrypt) == 'undefined') {
        throw "Could not find 'bCrypt'. Did you include bCrypt.js?";
    }
    var bcrypt = new bCrypt();

    var length = length || 16;
    var salt = passforge.salt_from_nickname(nickname);
    var bsalt = bcrypt.encode_salt(salt, log_rounds);
    if (passforge.DEBUG) {
        console.log('bcrypt salt: ' + bsalt);
    }

    if (length < 0) {
        throw 'minimum generated length is 0';
    }
    if (!passforge.result_callback) {
        throw "passforge.result_callback was not defined";
    }

    var start_time = new Date();

    // wrap the result_callback in function for processing, debugging, timing
    var callback = function(hashed) {
        var elapsed = (new Date() - start_time) / 1000;
        if (passforge.DEBUG) {
            console.log('hashed: ' + hashed);
        }
        derived = hashed.substr(bsalt.length, length);
        if (derived.length < length) {
            throw 'maximum generated length is ' + derived.length;
        }
        passforge.result_callback(derived, elapsed);
    }

    bcrypt.hashpw(password, bsalt, callback, passforge.status_callback);
}

// vim: set et tw=79 ts=4 sw=4
