"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
;
;
;
;
exports.defaultAlgorithm = 'aes-256-cbc';
exports.headerSize = 1;
class SecureVariable {
    constructor(value, password, replacer, algorithm) {
        this.data = Buffer.allocUnsafe(0);
        this.algorithm = algorithm;
        if (Buffer.isBuffer(value))
            this.data = value;
        else
            this.set(value, password, replacer);
    }
    get isEmpty() {
        return this.data.length < exports.headerSize;
    }
    get isEncrypted() {
        if (this.isEmpty)
            return false;
        return SecureVariable.getHeader(this.data).encrypted;
    }
    get rawData() {
        return this.data;
    }
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
    get(password, reviver) {
        return this.read(password, reviver).decoded;
    }
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
    encode(value, replacer) {
        return SecureVariable.encode(value, replacer);
    }
    encrypt(buffer, password) {
        return SecureVariable.encrypt(buffer, password, this.algorithm);
    }
    decode(encoded, reviver) {
        return SecureVariable.decode(encoded, reviver);
    }
    decrypt(buffer, password) {
        return SecureVariable.decrypt(buffer, password, this.algorithm);
    }
    static createHeader(encrypted) {
        const header = Buffer.allocUnsafe(exports.headerSize);
        header.writeUInt8(encrypted ? 1 : 0, 0);
        return header;
    }
    static getHeader(buf, offset = 0) {
        if (buf.length < exports.headerSize)
            throw new RangeError('Buffer has invalid size.');
        return {
            encrypted: buf.readInt8(offset) === 1
        };
    }
    static encode(value, replacer = v => v) {
        const encoded = JSON.stringify(value, (key, value) => replacer(value), 0);
        if (typeof encoded === 'undefined')
            return Buffer.allocUnsafe(0);
        return Buffer.from(encoded, 'utf8');
    }
    static encrypt(buf, password, algorithm = exports.defaultAlgorithm) {
        const cipher = crypto.createCipher(algorithm, password);
        cipher.update(buf);
        return cipher.final();
    }
    static decode(encoded, reviver = v => v) {
        if (encoded.length === 0)
            return undefined;
        return JSON.parse(encoded.toString('utf8'), (key, value) => reviver(value));
    }
    static decrypt(buf, password, algorithm = exports.defaultAlgorithm) {
        const decipher = crypto.createDecipher(algorithm, password);
        decipher.update(buf);
        return decipher.final();
    }
    static import(rawData, algorithm) {
        return new SecureVariable(rawData, undefined, undefined, algorithm);
    }
}
exports.SecureVariable = SecureVariable;
;
//# sourceMappingURL=secure-variable.js.map