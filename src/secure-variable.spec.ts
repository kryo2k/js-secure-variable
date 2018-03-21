import {
  SecureVariable,
  ISecureVariableReplacer,
  ISecureVariableReviver,
  headerSize
} from './secure-variable';

import { expect } from 'chai';
import 'mocha';

describe('SecureVariable<string>', () => {

  const
  TEST_1 = 'test-1',
  TEST_2 = 'test-2',
  TEST_3 = 'test-3';

  it('should let me create and read a value (plaintext)', () => {
    let instance = new SecureVariable<string>(TEST_1);

    expect(instance).to.instanceof(SecureVariable);
    expect(instance.isEmpty).to.eq(false);
    expect(instance.isEncrypted).to.eq(false);
    expect(instance.get()).to.eq(TEST_1);
  });

  it('should let me create and read a value (encrypted)', () => {
    let instance = new SecureVariable<string>(TEST_1, TEST_2);

    expect(instance).to.instanceof(SecureVariable);
    expect(instance.isEmpty).to.eq(false);
    expect(instance.isEncrypted).to.eq(true);
    expect(instance.get(TEST_2)).to.eq(TEST_1);
  });

  it('should prevent encrypted value from being seen', () => {
    let instance = new SecureVariable<string>(TEST_1, TEST_2);

    const detail = instance.read(TEST_2);

    expect(detail.header.encrypted).to.eq(true);
    expect(detail.encrypted).to.not.eq(undefined);
    expect(detail.encoded.equals(detail.encrypted||Buffer.allocUnsafe(0))).to.eq(false);
    expect(detail.decoded).to.eq(TEST_1);
  });

  it('should be able to do export import (plaintext)', () => {
    let
    instance1 = new SecureVariable<string>(TEST_1),
    instance2 = SecureVariable.import<string>(instance1.data, instance1.algorithm);
    expect(instance2.get()).to.eq(instance1.get());
  });

  it('should be able to do export import (encrypted)', () => {
    let
    instance1 = new SecureVariable<string>(TEST_1, TEST_2),
    instance2 = SecureVariable.import<string>(instance1.data, instance1.algorithm);
    expect(instance2.get(TEST_2)).to.eq(instance1.get(TEST_2));
  });
});

describe('SecureVariable<Object>', () => {

  class ComplexObject {

    value : number;

    constructor(value : number = 0) {
      this.value = value;
    }

    static wrap(v: number|ComplexObject) : ComplexObject {
      if(typeof v === 'object' && v instanceof ComplexObject)
        return v;

      return new ComplexObject(v);
    }
  };

  it('should allow me to serialize a complex object with replacer/reviver', () => {
    const
    passwd = 'TEST-1',
    replacer = (v : ComplexObject) => v.value,
    reviver  = (v : number) => ComplexObject.wrap(v);

    let
    complex1 = new ComplexObject(100),
    instance = new SecureVariable<ComplexObject>(complex1, passwd, replacer),
    complex2 = instance.get(passwd, reviver);

    expect(complex2).to.be.instanceof(ComplexObject);
    expect(complex2).to.deep.eq(complex1);
    expect(complex1.value).to.eq(complex2.value);
  });

  it('should allow me to serialize undefined', () => {

    const
    password = 'test',
    instance = new SecureVariable<string|undefined>(undefined, password);

    expect(instance.get(password)).to.eq(undefined);
  });

  it('should allow me to serialize NULL', () => {

    const
    password = 'test',
    instance = new SecureVariable<string|null>(null, password);

    expect(instance.get(password)).to.eq(null);
  });

  interface ISimpleObject {
    value1: any;
    value2 : any;
    options: {
      value1 : any;
      value2 : any;
    }
  };

  it('should serialize nested objects', () => {

    const
    password = 'test',
    instance = new SecureVariable<ISimpleObject>({
      value1: 'test1',
      value2: 'test2',
      options: {
        value1 : 'test3',
        value2 : 'test4'
      }
    }, password);

    expect(instance.get(password)).to.deep.eq({
      value1: 'test1',
      value2: 'test2',
      options: {
        value1: 'test3',
        value2: 'test4'
      }
    });
  });
});
