import { SecureVariable } from '../secure-variable';
import { inspect as _inspect } from 'util';

function inspect(v : any) : string {
  return _inspect(v, true, null, true);
}

const
password = 'secure',
value = Math.PI,
ptVar = new SecureVariable<number>(value),
ptRead = ptVar.read(),
enVar = new SecureVariable<number>(value, password),
enRead = enVar.read(password);

console.log('Plain Text:');
console.log(inspect({
  object : ptVar,
  read   : ptRead
}));

console.log('Encrypted:');
console.log(inspect({
  object : enVar,
  read   : enRead
}));
