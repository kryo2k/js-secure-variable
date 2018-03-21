"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const secure_variable_1 = require("../secure-variable");
const util_1 = require("util");
function inspect(v) {
    return util_1.inspect(v, true, null, true);
}
const password = 'secure', value = 'Secret Text', ptVar = new secure_variable_1.SecureVariable(value), ptRead = ptVar.read(), enVar = new secure_variable_1.SecureVariable(value, password), enRead = enVar.read(password);
console.log('Plain Text:');
console.log(inspect({
    object: ptVar,
    read: ptRead
}));
console.log('Encrypted:');
console.log(inspect({
    object: enVar,
    read: enRead
}));
//# sourceMappingURL=string.js.map