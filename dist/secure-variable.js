"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
;
;
;
;
/**
* Default cipher algorithm to use
*/
exports.defaultAlgorithm = 'aes-256-cbc';
/**
* Size of header after being created (in bytes).
*/
exports.headerSize = 1;
/**
* Main secure variable class.
*/
class SecureVariable {
    /**
    * Constructor allows class to be built from an unencrypted value (which is later encrypted)
    * or from a previously encrypted data buffer.
    */
    constructor(value, password, replacer, algorithm) {
        /**
        * Value & header data from the last "set"
        */
        this.data = Buffer.allocUnsafe(0);
        this.algorithm = algorithm;
        if (Buffer.isBuffer(value))
            this.data = value;
        else
            this.set(value, password, replacer);
    }
    /**
    * Determines if data has been set on this instance or not.
    */
    get isEmpty() {
        return this.data.length < exports.headerSize;
    }
    /**
    * Indicates if data is encrypted or not.
    */
    get isEncrypted() {
        if (this.isEmpty)
            return false;
        return SecureVariable.getHeader(this.data).encrypted;
    }
    /**
    * Set the internal value data. Allows using a replacer function to transform value
    * before encoding and encrypting it. If no password is provided, the value is saved
    * in plaintext encoded format.
    */
    set(value, password, replacer) {
        const usesEncryption = (pw) => {
            return typeof pw === 'string' && pw.length > 0;
        };
        let data = this.encode(value, replacer), header = Buffer.allocUnsafe(0);
        if (usesEncryption(password)) {
            header = SecureVariable.createHeader(true);
            data = this.encrypt(data, password);
        }
        else
            header = SecureVariable.createHeader(false);
        this.data = Buffer.concat([header, data]);
        return this;
    }
    /**
    * Get the last value set. A simplified version of "read" function.
    */
    get(password, reviver) {
        return this.read(password, reviver).decoded;
    }
    /**
    * Read the details from the last value set. Returns all parts of the decoding,
    * & decryption process for use in other logic. Supports a reviver function that
    * can be used to transform a decoded value back into it's original format.
    */
    read(password, reviver) {
        if (this.isEmpty)
            throw new RangeError('Buffer is empty.');
        const header = SecureVariable.getHeader(this.data);
        let encrypted = this.data.slice(1), encoded;
        if (header.encrypted) {
            if (typeof password === 'undefined')
                throw new TypeError('Data is encrypted and requires a password.');
            encoded = this.decrypt(encrypted, password);
        }
        else {
            encoded = encrypted;
            encrypted = undefined;
        }
        const decoded = this.decode(encoded, reviver);
        return { header, encrypted, encoded, decoded };
    }
    /**
    * Internal encode function. Short for SecureVariable.encode<T>
    */
    encode(value, replacer) {
        return SecureVariable.encode(value, replacer);
    }
    /**
    * Internal encrypt function. Short for SecureVariable.encrypt
    */
    encrypt(buffer, password) {
        return SecureVariable.encrypt(buffer, password, this.algorithm);
    }
    /**
    * Internal decode function. Short for SecureVariable.decode<T>
    */
    decode(encoded, reviver) {
        return SecureVariable.decode(encoded, reviver);
    }
    /**
    * Internal decrypt function. Short for SecureVariable.decrypt
    */
    decrypt(buffer, password) {
        return SecureVariable.decrypt(buffer, password, this.algorithm);
    }
    /**
    * Static helper function to create a header buffer from arguments.
    */
    static createHeader(encrypted) {
        const header = Buffer.allocUnsafe(exports.headerSize);
        header.writeUInt8(encrypted ? 1 : 0, 0);
        return header;
    }
    /**
    * Static helper function to read a header buffer.
    */
    static getHeader(buf, offset = 0) {
        if (buf.length < exports.headerSize)
            throw new RangeError('Buffer has invalid size.');
        return {
            encrypted: buf.readInt8(offset) === 1
        };
    }
    /**
    * Static helper function to encode a value into a Buffer using an optional replacer function.
    */
    static encode(value, replacer = v => v) {
        const encoded = JSON.stringify(replacer(value));
        if (typeof encoded === 'undefined')
            return Buffer.allocUnsafe(0);
        return Buffer.from(encoded, 'utf8');
    }
    /**
    * Static helper function to encrypt a value using given password and algorithm.
    */
    static encrypt(buf, password, algorithm = exports.defaultAlgorithm) {
        const cipher = crypto_1.createCipher(algorithm, password);
        return Buffer.concat([cipher.update(buf), cipher.final()]);
    }
    /**
    * Static helper function to decode a value from a Buffer using an optional reviver function.
    */
    static decode(encoded, reviver = v => v) {
        if (encoded.length === 0)
            return undefined;
        return reviver(JSON.parse(encoded.toString('utf8')));
    }
    /**
    * Static helper function to decrypt a buffer using given password and algorithm.
    */
    static decrypt(buf, password, algorithm = exports.defaultAlgorithm) {
        const decipher = crypto_1.createDecipher(algorithm, password);
        return Buffer.concat([decipher.update(buf), decipher.final()]);
    }
    /**
    * Static helper function to import a secure variable from data and algorithm. Short for
    * new SecureVariable<T>(buffer, undefined, undefined, algorithm);
    */
    static import(data, algorithm) {
        return new SecureVariable(data, undefined, undefined, algorithm);
    }
}
exports.SecureVariable = SecureVariable;
;
//# sourceMappingURL=secure-variable.js.map