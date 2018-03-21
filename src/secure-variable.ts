import * as crypto from 'crypto';

export interface ISecureVariableReplacer <T=any> {
  (value : T) : any;
};

export interface ISecureVariableReviver <T=any> {
  (value : any) : T;
};

export interface ISecureVariableHeader {
  encrypted : boolean;
};

export interface ISecureVariableDetail <T=any> {
  decoded   : T;
  encrypted : Buffer|undefined;
  encoded   : Buffer;
  header    : ISecureVariableHeader;
};

export var defaultAlgorithm = 'aes-256-cbc';
export const headerSize = 1;

export class SecureVariable <T=any> {

  algorithm ?: string;

  private data  : Buffer = Buffer.allocUnsafe(0);

  constructor(value : T|Buffer, password ?: string, replacer ?: ISecureVariableReplacer<T>, algorithm ?: string) {
    this.algorithm = algorithm;

    if(Buffer.isBuffer(value)) // set as raw data
      this.data = value;
    else
      this.set(value, password, replacer);
  }

  get isEmpty () : boolean {
    return this.data.length < headerSize;
  }

  get isEncrypted () : boolean {
    if(this.isEmpty) return false;
    return SecureVariable.getHeader(this.data).encrypted;
  }

  get rawData () : Buffer {
    return this.data;
  }

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

  get (password ?: string, reviver ?: ISecureVariableReviver<T>) : T {
    return this.read(password, reviver).decoded;
  }

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

  protected encode (value : T, replacer ?: ISecureVariableReplacer<T>) : Buffer {
    return SecureVariable.encode<T>(value, replacer);
  }

  protected encrypt (buffer : Buffer, password : string) : Buffer {
    return SecureVariable.encrypt(buffer, password, this.algorithm);
  }

  protected decode (encoded : Buffer, reviver ?: ISecureVariableReviver<T>) : T {
    return SecureVariable.decode<T>(encoded, reviver) as T;
  }

  protected decrypt (buffer : Buffer, password : string) : Buffer {
    return SecureVariable.decrypt(buffer, password, this.algorithm);
  }

  static createHeader (encrypted : boolean) : Buffer {
    const header = Buffer.allocUnsafe(headerSize);
    header.writeUInt8(encrypted ? 1 : 0, 0);
    return header;
  }

  static getHeader (buf : Buffer, offset : number = 0) : ISecureVariableHeader {

    if(buf.length < headerSize)
      throw new RangeError('Buffer has invalid size.');

    return {
      encrypted : buf.readInt8(offset) === 1
    };
  }

  static encode <T=any> (value : T, replacer : ISecureVariableReplacer<T> = v => v) : Buffer {
    const encoded = JSON.stringify(replacer(value));

    if(typeof encoded === 'undefined')
      return Buffer.allocUnsafe(0);

    return Buffer.from(encoded, 'utf8');
  }

  static encrypt (buf : Buffer, password : string, algorithm : string = defaultAlgorithm) : Buffer {
    const cipher = crypto.createCipher(algorithm, password);
    return Buffer.concat([cipher.update(buf), cipher.final()]);
  }

  static decode <T=any> (encoded : Buffer, reviver : ISecureVariableReviver<T> = v => v as T) : T|undefined {
    if(encoded.length === 0)
      return undefined;

    return reviver(JSON.parse(encoded.toString('utf8')));
  }

  static decrypt (buf : Buffer, password : string, algorithm : string = defaultAlgorithm) : Buffer {
    const decipher = crypto.createDecipher(algorithm, password);
    return Buffer.concat([decipher.update(buf), decipher.final()]);
  }

  static import <T=any> (rawData : Buffer, algorithm ?: string) : SecureVariable<T> {
    return new SecureVariable<T>(rawData, undefined, undefined, algorithm);
  }
};
