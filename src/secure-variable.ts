import { createCipher, createDecipher } from 'crypto';

/**
* Interface for value replacer function.
*/

export interface ISecureVariableReplacer <T=any> {
  (value : T) : any;
};

/**
* Interface for value reviver function.
*/

export interface ISecureVariableReviver <T=any> {
  (value : any) : T;
};

/**
* Interface for value header
*/

export interface ISecureVariableHeader {
  encrypted : boolean;
};

/**
* Interface for value detail
*/

export interface ISecureVariableDetail <T=any> {
  decoded   : T;
  encrypted : Buffer|undefined;
  encoded   : Buffer;
  header    : ISecureVariableHeader;
};

/**
* Default cipher algorithm to use
*/

export var defaultAlgorithm = 'aes-256-cbc';

/**
* Size of header after being created (in bytes).
*/
export const headerSize = 1;

/**
* Main secure variable class.
*/
export class SecureVariable <T=any> {

  /**
  * Cipher algorithm to use for this instance.
  */
  algorithm ?: string;

  /**
  * Value & header data from the last "set"
  */
  data : Buffer = Buffer.allocUnsafe(0);

  /**
  * Constructor allows class to be built from an unencrypted value (which is later encrypted)
  * or from a previously encrypted data buffer.
  */
  constructor(value : T|Buffer, password ?: string, replacer ?: ISecureVariableReplacer<T>, algorithm ?: string) {
    this.algorithm = algorithm;

    if(Buffer.isBuffer(value)) // set as raw data
      this.data = value;
    else
      this.set(value, password, replacer);
  }

  /**
  * Determines if data has been set on this instance or not.
  */

  get isEmpty () : boolean {
    return this.data.length < headerSize;
  }

  /**
  * Indicates if data is encrypted or not.
  */

  get isEncrypted () : boolean {
    if(this.isEmpty) return false;
    return SecureVariable.getHeader(this.data).encrypted;
  }

  /**
  * Set the internal value data. Allows using a replacer function to transform value
  * before encoding and encrypting it. If no password is provided, the value is saved
  * in plaintext encoded format.
  */
  set (value : T, password ?: string, replacer ?: ISecureVariableReplacer<T>) : SecureVariable<T> {

    const
    usesEncryption = (pw : string|undefined) : pw is string => {
      return typeof pw === 'string' && pw.length > 0;
    };

    let
    data   : Buffer = this.encode(value, replacer),
    header : Buffer = Buffer.allocUnsafe(0);

    if(usesEncryption(password)) { // encrypted header
      header = SecureVariable.createHeader(true);
      data   = this.encrypt(data, password);
    }
    else // unencrypted header
      header = SecureVariable.createHeader(false);

    this.data = Buffer.concat([header, data]);

    return this;
  }

  /**
  * Get the last value set. A simplified version of "read" function.
  */
  get (password ?: string, reviver ?: ISecureVariableReviver<T>) : T {
    return this.read(password, reviver).decoded;
  }

  /**
  * Read the details from the last value set. Returns all parts of the decoding,
  * & decryption process for use in other logic. Supports a reviver function that
  * can be used to transform a decoded value back into it's original format.
  */
  read (password ?: string, reviver ?: ISecureVariableReviver<T>) : ISecureVariableDetail<T> {

    if(this.isEmpty)
      throw new RangeError('Buffer is empty.');

    const
    header = SecureVariable.getHeader(this.data);

    let
    encrypted : Buffer|undefined = this.data.slice(1),
    encoded   : Buffer;

    if(header.encrypted) {

      if(typeof password === 'undefined')
        throw new TypeError('Data is encrypted and requires a password.');

      encoded = this.decrypt(encrypted, password);
    }
    else {
      encoded   = encrypted;
      encrypted = undefined;
    }

    const
    decoded = this.decode(encoded, reviver);

    return { header, encrypted, encoded, decoded };
  }

  /**
  * Internal encode function. Short for SecureVariable.encode<T>
  */
  protected encode (value : T, replacer ?: ISecureVariableReplacer<T>) : Buffer {
    return SecureVariable.encode<T>(value, replacer);
  }

  /**
  * Internal encrypt function. Short for SecureVariable.encrypt
  */
  protected encrypt (buffer : Buffer, password : string) : Buffer {
    return SecureVariable.encrypt(buffer, password, this.algorithm);
  }

  /**
  * Internal decode function. Short for SecureVariable.decode<T>
  */
  protected decode (encoded : Buffer, reviver ?: ISecureVariableReviver<T>) : T {
    return SecureVariable.decode<T>(encoded, reviver) as T;
  }

  /**
  * Internal decrypt function. Short for SecureVariable.decrypt
  */
  protected decrypt (buffer : Buffer, password : string) : Buffer {
    return SecureVariable.decrypt(buffer, password, this.algorithm);
  }

  /**
  * Static helper function to create a header buffer from arguments.
  */
  static createHeader (encrypted : boolean) : Buffer {
    const header = Buffer.allocUnsafe(headerSize);
    header.writeUInt8(encrypted ? 1 : 0, 0);
    return header;
  }

  /**
  * Static helper function to read a header buffer.
  */
  static getHeader (buf : Buffer, offset : number = 0) : ISecureVariableHeader {

    if(buf.length < headerSize)
      throw new RangeError('Buffer has invalid size.');

    return {
      encrypted : buf.readInt8(offset) === 1
    };
  }

  /**
  * Static helper function to encode a value into a Buffer using an optional replacer function.
  */
  static encode <T=any> (value : T, replacer : ISecureVariableReplacer<T> = v => v) : Buffer {
    const encoded = JSON.stringify(replacer(value));

    if(typeof encoded === 'undefined')
      return Buffer.allocUnsafe(0);

    return Buffer.from(encoded, 'utf8');
  }

  /**
  * Static helper function to encrypt a value using given password and algorithm.
  */
  static encrypt (buf : Buffer, password : string, algorithm : string = defaultAlgorithm) : Buffer {
    const cipher = createCipher(algorithm, password);
    return Buffer.concat([cipher.update(buf), cipher.final()]);
  }

  /**
  * Static helper function to decode a value from a Buffer using an optional reviver function.
  */
  static decode <T=any> (encoded : Buffer, reviver : ISecureVariableReviver<T> = v => v as T) : T|undefined {
    if(encoded.length === 0)
      return undefined;

    return reviver(JSON.parse(encoded.toString('utf8')));
  }

  /**
  * Static helper function to decrypt a buffer using given password and algorithm.
  */
  static decrypt (buf : Buffer, password : string, algorithm : string = defaultAlgorithm) : Buffer {
    const decipher = createDecipher(algorithm, password);
    return Buffer.concat([decipher.update(buf), decipher.final()]);
  }

  /**
  * Static helper function to import a secure variable from data and algorithm. Short for
  * new SecureVariable<T>(buffer, undefined, undefined, algorithm);
  */
  static import <T=any> (data : Buffer, algorithm ?: string) : SecureVariable<T> {
    return new SecureVariable<T>(data, undefined, undefined, algorithm);
  }
};
