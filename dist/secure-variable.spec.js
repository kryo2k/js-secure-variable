"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const secure_variable_1 = require("./secure-variable");
const chai_1 = require("chai");
require("mocha");
describe('SecureVariable<string>', () => {
    const TEST_1 = 'test-1', TEST_2 = 'test-2', TEST_3 = 'test-3';
    it('should let me create and read a value (plaintext)', () => {
        let instance = new secure_variable_1.SecureVariable(TEST_1);
        chai_1.expect(instance).to.instanceof(secure_variable_1.SecureVariable);
        chai_1.expect(instance.isEmpty).to.eq(false);
        chai_1.expect(instance.isEncrypted).to.eq(false);
        chai_1.expect(instance.get()).to.eq(TEST_1);
    });
    it('should let me create and read a value (encrypted)', () => {
        let instance = new secure_variable_1.SecureVariable(TEST_1, TEST_2);
        chai_1.expect(instance).to.instanceof(secure_variable_1.SecureVariable);
        chai_1.expect(instance.isEmpty).to.eq(false);
        chai_1.expect(instance.isEncrypted).to.eq(true);
        chai_1.expect(instance.get(TEST_2)).to.eq(TEST_1);
    });
    it('should prevent encrypted value from being seen', () => {
        let instance = new secure_variable_1.SecureVariable(TEST_1, TEST_2);
        const detail = instance.read(TEST_2);
        chai_1.expect(detail.header.encrypted).to.eq(true);
        chai_1.expect(detail.encrypted).to.not.eq(undefined);
        chai_1.expect(detail.encoded.equals(detail.encrypted || Buffer.allocUnsafe(0))).to.eq(false);
        chai_1.expect(detail.decoded).to.eq(TEST_1);
    });
    it('should be able to do export import (plaintext)', () => {
        let instance1 = new secure_variable_1.SecureVariable(TEST_1), instance2 = secure_variable_1.SecureVariable.import(instance1.rawData);
        chai_1.expect(instance2.get()).to.eq(instance1.get());
    });
    it('should be able to do export import (encrypted)', () => {
        let instance1 = new secure_variable_1.SecureVariable(TEST_1, TEST_2), instance2 = secure_variable_1.SecureVariable.import(instance1.rawData);
        chai_1.expect(instance2.get(TEST_2)).to.eq(instance1.get(TEST_2));
    });
});
describe('SecureVariable<Object>', () => {
    class ComplexObject {
        constructor(value = 0) {
            this.value = value;
        }
        static wrap(v) {
            if (typeof v === 'object' && v instanceof ComplexObject)
                return v;
            return new ComplexObject(v);
        }
    }
    ;
    it('should allow me to serialize a complex object with replacer/reviver', () => {
        const passwd = 'TEST-1', replacer = (v) => v.value, reviver = (v) => ComplexObject.wrap(v);
        let complex1 = new ComplexObject(100), instance = new secure_variable_1.SecureVariable(complex1, passwd, replacer), complex2 = instance.get(passwd, reviver);
        chai_1.expect(complex2).to.be.instanceof(ComplexObject);
        chai_1.expect(complex2).to.deep.eq(complex1);
        chai_1.expect(complex1.value).to.eq(complex2.value);
    });
    it('should allow me to serialize undefined', () => {
        const password = 'test', instance = new secure_variable_1.SecureVariable(undefined, password);
        chai_1.expect(instance.get(password)).to.eq(undefined);
    });
    it('should allow me to serialize NULL', () => {
        const password = 'test', instance = new secure_variable_1.SecureVariable(null, password);
        chai_1.expect(instance.get(password)).to.eq(null);
    });
});
//# sourceMappingURL=secure-variable.spec.js.map