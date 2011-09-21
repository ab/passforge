/*
 * passforge.js
 */

/*
 * Convert a hexadecimal string to a raw ascii byte stream.
 */
function hex2rstr(input) {
	var output = "";
	var len = input.length;
	var ibyte;
	for (var i = 0; i < len; i += 2) {
		ibyte = (hexcode_to_int(input.charCodeAt(i)) << 4)
				| ((i + 1 < len) ? hexcode_to_int(input.charCodeAt(i+1)) : 0);
		output += String.fromCharCode(ibyte);
	}
	return output
}

function hexcode_to_int(code) {
	// 0-9
	if (code <= 57 && code >= 48) {
		return code - 48;
	}

	// uppercase A-F
	if (code <= 70 && code >= 65) {
		return code - 65 + 10;
	}

	// lowercase a-f
	if (code <= 102 && code >= 97) {
		return code - 97 + 10;
	}

	return NaN;
}

function hex2b64(input) {
	return rstr2b64(hex2rstr(input));
}

var passforge = passforge || {};

/* User-configurable parameters and callbacks */
passforge.length = 8;
passforge.iterations = 1000;
passforge.require_digits = false; // TODO (notimplemented)
passforge.status_callback = function() {};
passforge.return_callback = function(key, elapsed) {
	console.log("[default return_callback]");
	console.log("Derived key " + key + " in " + elapsed + "s");
};

/* A wrapper function to truncate the derived key to the correct length. */
passforge.apply_key_policy = function(key, elapsed) {
	var b64key = hex2b64(key);

	// truncate to desired length
	b64key = b64key.substring(0, passforge.length);

	// use a url-safe variant of base64
	b64key = b64key.replace(/\+/g, '-').replace(/\//g, '_');

	if (passforge.require_digits) {
		console.log('require_digits not yet implemented');
		// TODO
	}
	return passforge.return_callback(b64key, elapsed);
}


passforge.config = function(pass_length, iterations, status_callback,
		return_callback) {
	passforge.length = pass_length;
	passforge.iterations = iterations;
	passforge.status_callback = status_callback;
	passforge.return_callback = return_callback;
}

passforge.pwgen = function(nickname, master, salt, asynchronous) {
	// round up bytes required
	var bytes = Math.ceil(passforge.length * 3 / 4);

	// initialize PBKDF2 module
	var pbkdf2 = new PBKDF2(master + nickname, salt, passforge.iterations,
			bytes);

	// derive key
	if (asynchronous) {
		pbkdf2.deriveKey(passforge.status_callback, passforge.apply_key_policy);
		return true;
	} else {
		pbkdf2.deriveKeySync(passforge.apply_key_policy);
		return true;
	}
};
