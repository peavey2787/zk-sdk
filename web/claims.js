// Builds the typed claim JSON the Rust `Predicate` deserializes. Pure data: no cryptography here.
export const INT_TYPES = ["u32", "i32", "u64", "i64", "u128", "i128"];
export const OPS = { lt: "<", le: "<=", gt: ">", ge: ">=", eq: "==", ne: "!=" };

// `fields` are the form rows a family shows; `operands` name its public-or-private operands.
export const FAMILIES = {
  opens: { title: "Knowledge of a commitment's opening", fields: ["valueA"] },
  compare: { title: "Committed value vs a public bound", fields: ["valueA", "op", "bound"] },
  range: { title: "Committed value within a range", fields: ["valueA", "lo", "hi", "ends"] },
  compare_committed: { title: "Committed value vs another committed value", fields: ["valueA", "valueB", "op"] },
  conserve: { title: "Conservation: inputs = outputs + fee", fields: ["inputs", "outputs", "fee"] },
  total: { title: "Total of committed values vs a public bound", fields: ["inputs", "op", "bound"] },
  arithmetic: { title: "Product: x * y + z (op) t", fields: ["op", "operands"], operands: ["x", "y", "z", "t"] },
  divide: {
    title: "Division: dividend = quotient * divisor + remainder",
    fields: ["operands"],
    operands: ["dividend", "divisor", "quotient", "remainder"],
  },
};

const list = (text) => text.split(",").map((item) => item.trim()).filter(Boolean);

// The private values to commit to, in the order `buildClaim` consumes their commitments.
export function privateValues(family, form) {
  switch (family) {
    case "conserve":
      return [...list(form.inputs), ...list(form.outputs)];
    case "total":
      return list(form.inputs);
    case "arithmetic":
    case "divide":
      return form.operands.filter((o) => o.mode === "private").map((o) => o.value);
    case "compare_committed":
      return [form.valueA, form.valueB];
    default:
      return [form.valueA];
  }
}

// Private operands become commitments, in order; public ones stay decimal strings.
function operandClaims(form, commitments) {
  let next = 0;
  return form.operands.map((o) => (o.mode === "private" ? commitments[next++] : o.value));
}

// `commitments` are the public commitment strings, in claim order.
export function buildClaim(family, form, commitments) {
  switch (family) {
    case "opens":
      return { kind: "opens", commitment: commitments[0] };
    case "compare":
      return { kind: "compare", commitment: commitments[0], op: form.op, bound: form.bound };
    case "range":
      return {
        kind: "range", commitment: commitments[0], lo: form.lo, hi: form.hi,
        lo_inclusive: form.loInclusive, hi_inclusive: form.hiInclusive,
      };
    case "compare_committed":
      return { kind: "compare_committed", left: commitments[0], right: commitments[1], op: form.op };
    case "conserve": {
      const inputs = list(form.inputs).length;
      return {
        kind: "sum", plus: commitments.slice(0, inputs), minus: commitments.slice(inputs),
        plus_constant: "0", minus_constant: form.fee, op: "eq",
      };
    }
    case "total":
      return { kind: "sum", plus: commitments, minus: [], plus_constant: "0", minus_constant: form.bound, op: form.op };
    case "arithmetic": {
      const [x, y, z, t] = operandClaims(form, commitments);
      return { kind: "arithmetic", x, y, z, t, op: form.op };
    }
    case "divide": {
      const [dividend, divisor, quotient, remainder] = operandClaims(form, commitments);
      return { kind: "divide", dividend, divisor, quotient, remainder };
    }
    default:
      throw new Error(`unknown predicate family ${family}`);
  }
}
