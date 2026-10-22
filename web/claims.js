// Builds the typed claim JSON the Rust `Predicate` deserializes. Pure data: no cryptography here.
export const INT_TYPES = ["u32", "i32", "u64", "i64", "u128", "i128"];
export const OPS = { lt: "<", le: "<=", gt: ">", ge: ">=", eq: "==", ne: "!=" };

export const FAMILIES = {
  opens: { title: "Knowledge of a commitment's opening", committed: 1, fields: [] },
  compare: { title: "Committed value vs a public bound", committed: 1, fields: ["op", "bound"] },
  range: { title: "Committed value within a range", committed: 1, fields: ["lo", "hi", "ends"] },
  compare_committed: { title: "Committed value vs another committed value", committed: 2, fields: ["op"] },
};

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
    default:
      throw new Error(`unknown predicate family ${family}`);
  }
}
