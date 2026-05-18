// Minimal JSON Schema validator — just the subset our tool schemas use.
// No deps. Throws on invalid input with a path-prefixed error message.
//
// Supported keywords: type (object/array/string/boolean/number),
// required, properties, items, enum, minItems, maxItems, maxLength,
// minLength, additionalProperties (only as `false` — strict).

const TYPE_OF = (v) => {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v;
};

export function validate(schema, value, path = 'arguments') {
  if (!schema) return;
  const t = schema.type;
  if (t === 'object') {
    if (TYPE_OF(value) !== 'object') throw new Error(`${path}: expected object, got ${TYPE_OF(value)}`);
    for (const req of schema.required || []) {
      if (!(req in value)) throw new Error(`${path}: missing required property "${req}"`);
    }
    if (schema.additionalProperties === false) {
      const allowed = new Set(Object.keys(schema.properties || {}));
      for (const k of Object.keys(value)) {
        if (!allowed.has(k)) throw new Error(`${path}: unexpected property "${k}"`);
      }
    }
    for (const [k, sub] of Object.entries(schema.properties || {})) {
      if (k in value) validate(sub, value[k], `${path}.${k}`);
    }
  } else if (t === 'array') {
    if (!Array.isArray(value)) throw new Error(`${path}: expected array, got ${TYPE_OF(value)}`);
    if (schema.minItems != null && value.length < schema.minItems) throw new Error(`${path}: minItems=${schema.minItems}, got length=${value.length}`);
    if (schema.maxItems != null && value.length > schema.maxItems) throw new Error(`${path}: maxItems=${schema.maxItems}, got length=${value.length}`);
    if (schema.items) for (let i = 0; i < value.length; i++) validate(schema.items, value[i], `${path}[${i}]`);
  } else if (t === 'string') {
    if (typeof value !== 'string') throw new Error(`${path}: expected string, got ${TYPE_OF(value)}`);
    if (schema.enum && !schema.enum.includes(value)) throw new Error(`${path}: must be one of [${schema.enum.join(', ')}]`);
    if (schema.maxLength != null && value.length > schema.maxLength) throw new Error(`${path}: maxLength=${schema.maxLength}, got length=${value.length}`);
    if (schema.minLength != null && value.length < schema.minLength) throw new Error(`${path}: minLength=${schema.minLength}, got length=${value.length}`);
  } else if (t === 'boolean') {
    if (typeof value !== 'boolean') throw new Error(`${path}: expected boolean, got ${TYPE_OF(value)}`);
  } else if (t === 'number' || t === 'integer') {
    if (typeof value !== 'number') throw new Error(`${path}: expected number, got ${TYPE_OF(value)}`);
    if (t === 'integer' && !Number.isInteger(value)) throw new Error(`${path}: expected integer`);
    if (schema.minimum != null && value < schema.minimum) throw new Error(`${path}: < minimum (${schema.minimum})`);
    if (schema.maximum != null && value > schema.maximum) throw new Error(`${path}: > maximum (${schema.maximum})`);
  }
}
