/// <reference types="node" />
/**
* Interface for value replacer function.
*/
export interface ISecureVariableReplacer<T = any> {
    (value: T): any;
}
/**
* Interface for value reviver function.
*/
export interface ISecureVariableReviver<T = any> {
    (value: any): T;
}
/**
* Interface for value header
*/
export interface ISecureVariableHeader {
    encrypted: boolean;
}
/**
* Interface for value detail
*/
export interface ISecureVariableDetail<T = any> {
    decoded: T;
    encrypted: Buffer | undefined;
    encoded: Buffer;
    header: ISecureVariableHeader;
}
/**
* Default cipher algorithm to use
*/
export declare var defaultAlgorithm: string;
/**
* Size of header after being created (in bytes).
*/
export declare const headerSize = 1;
/**
* Main secure variable class.
*/
export declare class SecureVariable<T = any> {
    /**
    * Cipher algorithm to use for this instance.
    */
    algorithm?: string;
    /**
    * Value & header data from the last "set"
    */
    data: Buffer;
    /**
    * Constructor allows class to be built from an unencrypted value (which is later encrypted)
    * or from a previously encrypted data buffer.
    */
    constructor(value: T | Buffer, password?: string, replacer?: ISecureVariableReplacer<T>, algorithm?: string);
    /**
    * Determines if data has been set on this instance or not.
    */
    readonly isEmpty: boolean;
    /**
    * Indicates if data is encrypted or not.
    */
    readonly isEncrypted: boolean;
    /**
    * Set the internal value data. Allows using a replacer function to transform value
    * before encoding and encrypting it. If no password is provided, the value is saved
    * in plaintext encoded format.
    */
    set(value: T, password?: string, replacer?: ISecureVariableReplacer<T>): SecureVariable<T>;
    /**
    * Get the last value set. A simplified version of "read" function.
    */
    get(password?: string, reviver?: ISecureVariableReviver<T>): T;
    /**
    * Read the details from the last value set. Returns all parts of the decoding,
    * & decryption process for use in other logic. Supports a reviver function that
    * can be used to transform a decoded value back into it's original format.
    */
    read(password?: string, reviver?: ISecureVariableReviver<T>): ISecureVariableDetail<T>;
    /**
    * Internal encode function. Short for SecureVariable.encode<T>
    */
    protected encode(value: T, replacer?: ISecureVariableReplacer<T>): Buffer;
    /**
    * Internal encrypt function. Short for SecureVariable.encrypt
    */
    protected encrypt(buffer: Buffer, password: string): Buffer;
    /**
    * Internal decode function. Short for SecureVariable.decode<T>
    */
    protected decode(encoded: Buffer, reviver?: ISecureVariableReviver<T>): T;
    /**
    * Internal decrypt function. Short for SecureVariable.decrypt
    */
    protected decrypt(buffer: Buffer, password: string): Buffer;
    /**
    * Static helper function to create a header buffer from arguments.
    */
    static createHeader(encrypted: boolean): Buffer;
    /**
    * Static helper function to read a header buffer.
    */
    static getHeader(buf: Buffer, offset?: number): ISecureVariableHeader;
    /**
    * Static helper function to encode a value into a Buffer using an optional replacer function.
    */
    static encode<T = any>(value: T, replacer?: ISecureVariableReplacer<T>): Buffer;
    /**
    * Static helper function to encrypt a value using given password and algorithm.
    */
    static encrypt(buf: Buffer, password: string, algorithm?: string): Buffer;
    /**
    * Static helper function to decode a value from a Buffer using an optional reviver function.
    */
    static decode<T = any>(encoded: Buffer, reviver?: ISecureVariableReviver<T>): T | undefined;
    /**
    * Static helper function to decrypt a buffer using given password and algorithm.
    */
    static decrypt(buf: Buffer, password: string, algorithm?: string): Buffer;
    /**
    * Static helper function to import a secure variable from data and algorithm. Short for
    * new SecureVariable<T>(buffer, undefined, undefined, algorithm);
    */
    static import<T = any>(data: Buffer, algorithm?: string): SecureVariable<T>;
}
