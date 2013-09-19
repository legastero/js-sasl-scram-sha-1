(function(root, factory) {
  if (typeof exports === 'object') {
    // CommonJS
    factory(exports, module, require('crypto'), require('buffer'));
  } else if (typeof define === 'function' && define.amd) {
    // AMD
    define(['exports', 'module', 'crypto', 'buffer'], factory);
  }
}(this, function(exports, module, crypto, buffer) {

    var Buffer = buffer.Buffer;
 
    /**
     * SCRAM-SHA-1 `Mechanism` constructor.
     *
     * This class implements the SCRAM-SHA-1 SASL mechanism.
     *
     * References:
     *  - [RFC 5802](http://tools.ietf.org/html/rfc5802)
     *
     * @api public
     */
    function Mechanism(options) {
        options = options || {};
        this._genNonce = options.genNonce || genNonce(32);
        this._stage = 0;
    }

    Mechanism.prototype.name = 'SCRAM-SHA-1';
    Mechanism.prototype.clientFirst = true;

    /**
     * Encode a response using given credentials.
     *
     * Options:
     *  - `username`
     *  - `password`
     *  - `authzid`
     *
     * @param {object} cred
     * @api public
     */
    Mechanism.prototype.response = function (cred) {
        return responses[this._stage](this, cred); 
    };

    /**
     * Decode a challenge issued by the server.
     *
     * @param {String} chal
     * @return {Mechanism} for chaining
     * @api public
     */
    Mechanism.prototype.challenge = function (chal) {
        var values = parse(chal);

        this._salt = new Buffer(values.s || '', 'base64').toString('binary');
        this._iterationCount = parseInt(values.i, 10);
        this._nonce = values.r;
        this._verifier = values.v;
        this._error = values.e;
        this._challenge = chal;

        return this;
    };


    var responses = {};
    responses[0] = function (mech, cred) {
        mech._cnonce = mech._genNonce();

        var authzid = '';
        if (cred.authzid) {
            authzid = 'a=' + saslname(cred.authzid);
        }

        mech._gs2Header = 'n,' + authzid + ',';

        var nonce = 'r=' + mech._cnonce;
        var username = 'n=' + saslname(cred.username);

        mech._clientFirstMessageBare = username + ',' + nonce;
        var result = mech._gs2Header + mech._clientFirstMessageBare

        mech._stage = 1;

        return result;
    };
    responses[1] = function (mech, cred) {
        var gs2Header = new Buffer(mech._gs2Header).toString('base64');

        mech._clientFinalMessageWithoutProof = 'c=' + gs2Header + ',r=' + mech._nonce;

        var saltedPassword, clientKey, serverKey;
        if (cred.clientKey && cred.serverKey) {
            clientKey = cred.clientKey;
            serverKey = cred.serverKey;
        } else {
            saltedPassword = cred.saltedPassword || Hi(cred.password, mech._salt, mech._iterationCount);
            clientKey = HMAC(saltedPassword, 'Client Key');
            serverKey = HMAC(saltedPassword, 'Server Key');
        }

        var storedKey = H(clientKey);
        var authMessage = mech._clientFirstMessageBare + ',' +
                          mech._challenge + ',' + 
                          mech._clientFinalMessageWithoutProof;
        var clientSignature = HMAC(storedKey, authMessage);

        var xorstuff = XOR(clientKey, clientSignature);

        var clientProof = new Buffer(xorstuff, 'binary').toString('base64');

        mech._serverSignature = HMAC(serverKey, authMessage);

        var result = mech._clientFinalMessageWithoutProof + ',p=' + clientProof;

        mech._stage = 2;

        mech.cache = {
            saltedPassword: saltedPassword,
            clientKey: clientKey,
            serverKey: serverKey
        };

        return result;
    };
    responses[2] = function (mech, cred) {
        // TODO: Signal errors 
        return '';
    };

    /**
     * Create a SHA-1 HMAC.
     *
     * @param {String} key
     * @param {String} msg
     * @api private
     */
    function HMAC(key, msg) {
        return crypto.createHmac('sha1', key).update(msg).digest('binary');
    }

    /**
     * Iteratively create an HMAC, with a salt.
     *
     * @param {String} text
     * @param {String} salt
     * @param {Number} iterations
     * @api private
     */
    function Hi(text, salt, iterations) {
        var ui1 = HMAC(text, salt + '\0\0\0\1');
        var ui = ui1;
        for (var i = 0; i < iterations - 1; i++) {
            ui1 = HMAC(text, ui1);
            ui = XOR(ui, ui1);
        }
        return ui;
    }

    /**
     * Create a SHA-1 hash.
     *
     * @param {String} text
     * @api private
     */
    function H(text) {
        return crypto.createHash('sha1').update(text).digest('binary');
    }

    /**
     * String XOR
     *
     * @param {String} a
     * @param {String} b
     * @api private
     */
    function XOR(a, b) {
        a = new Buffer(a, 'binary');
        b = new Buffer(b, 'binary');

        var len = Math.min(a.length, b.length);
        result = [];
        for (var i = 0; i < len; i++) {
            result.push(a[i] ^ b[i]);
        }
        result = new Buffer(result, 'binary');
        return result.toString('binary');
    }

    /**
     * Escape special characters in username values.
     *
     * @param {String} name
     * @api private
     */
    function saslname(name) {
        var escaped = [];
        var curr = '';
        for (var i = 0; i < name.length; i++) {
            curr = name[i];
            if (curr === ',') {
                escaped.push('=2C');
            } else if (curr === '=') {
                escaped.push('=3D');
            } else {
                escaped.push(curr);
            }
        }
        return escaped.join('');
    }

    /**
     * Parse challenge.
     *
     * @api private
     */
    function parse(chal) {
        var dtives = {};
        var tokens = chal.split(/,(?=(?:[^"]|"[^"]*")*$)/);
        for (var i = 0, len = tokens.length; i < len; i++) {
            var dtiv = /(\w+)=["]?([^"]+)["]?$/.exec(tokens[i]);
            if (dtiv) {
                dtives[dtiv[1]] = dtiv[2];
            }
        }
        return dtives;
    }
  
 
    /**
    * Return a unique nonce with the given `len`.
    *
    *     genNonce(10)();
    *     // => "FDaS435D2z"
    *
    * @param {Number} len
    * @return {Function}
    * @api private
    */
    function genNonce(len) {
        var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        var charlen = chars.length;

        return function() {
            var buf = [];
            for (var i = 0; i < len; ++i) {
                buf.push(chars[Math.random() * charlen | 0]);
            }
            return buf.join('');
        }
    }

    exports = module.exports = Mechanism;
}));
