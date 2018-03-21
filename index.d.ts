/// <reference types="node" />
export interface ISecureVariableReplacer<T = any> {
    (value: T): any;
}
export interface ISecureVariableReviver<T = any> {
    (value: any): T;
}
export interface ISecureVariableHeader {
    encrypted: boolean;
}
export interface ISecureVariableDetail<T = any> {
    decoded: T;
    encrypted: Buffer | undefined;
    encoded: Buffer;
    header: ISecureVariableHeader;
}
export declare var defaultAlgorithm: string;
export declare const headerSize = 1;
export declare class SecureVariable<T = any> {
    algorithm?: string;
    private data;
    constructor(value: T | Buffer, password?: string, replacer?: ISecureVariableReplacer<T>, algorithm?: string);
    readonly isEmpty: boolean;
    readonly isEncrypted: boolean;
    readonly rawData: Buffer;
    set(value: T, password?: string, replacer?: ISecureVariableReplacer<T>): SecureVariable<T>;
    get(password?: string, reviver?: ISecureVariableReviver<T>): T;
    read(password?: string, reviver?: ISecureVariableReviver<T>): ISecureVariableDetail<T>;
    protected encode(value: T, replacer?: ISecureVariableReplacer<T>): Buffer;
    protected encrypt(buffer: Buffer, password: string): Buffer;
    protected decode(encoded: Buffer, reviver?: ISecureVariableReviver<T>): T;
    protected decrypt(buffer: Buffer, password: string): Buffer;
    static createHeader(encrypted: boolean): Buffer;
    static getHeader(buf: Buffer, offset?: number): ISecureVariableHeader;
    static encode<T = any>(value: T, replacer?: ISecureVariableReplacer<T>): Buffer;
    static encrypt(buf: Buffer, password: string, algorithm?: string): Buffer;
    static decode<T = any>(encoded: Buffer, reviver?: ISecureVariableReviver<T>): T | undefined;
    static decrypt(buf: Buffer, password: string, algorithm?: string): Buffer;
    static import<T = any>(rawData: Buffer, algorithm?: string): SecureVariable<T>;
}
