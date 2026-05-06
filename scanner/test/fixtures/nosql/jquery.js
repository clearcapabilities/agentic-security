// jQuery / regex / string usage of operator-shaped tokens — should NOT trigger
const $ = require('jquery');
$.where = function () { return 'jquery noop'; };
$.find('div');

const orPattern = /\$or/;   // regex literal containing "$or"
const msg = "Hint: try $or to combine"; // string content
console.log(orPattern, msg);
