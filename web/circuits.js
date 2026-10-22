// Per-circuit form fields, and the public statement a verifier would independently expect.
const P = 2130706433n;

export const circuits = {
  age_over: {
    title: "Over a threshold age",
    private: [{ name: "age", label: "Private age", value: 20, max: 255 }],
    public: [{ name: "threshold", label: "Public threshold", value: 18, max: 255 }],
    // circom order: outputs first, then public inputs
    statement: ({ age, threshold }) => [age > threshold ? 1n : 0n, threshold],
    describe: ([holds]) => (holds ? "age is over the threshold" : "age is not over the threshold"),
  },
  millionaires: {
    title: "Millionaires",
    private: [
      { name: "alice", label: "Alice's wealth (private)", value: 2000000, max: 536870911 },
      { name: "bob", label: "Bob's wealth (private)", value: 1000000, max: 536870911 },
    ],
    public: [],
    statement: ({ alice, bob }) => [alice > bob ? 1n : 0n],
    describe: ([holds]) => (holds ? "Alice is richer" : "Alice is not richer"),
  },
  arithmetic: {
    title: "Arithmetic (y = (x * secret + x)^2 + 3)",
    private: [{ name: "secret", label: "Private secret", value: 7, max: 1000000 }],
    public: [{ name: "x", label: "Public x", value: 5, max: 1000000 }],
    statement: ({ x, secret }) => [(((x * secret + x) ** 2n) + 3n) % P, x],
    describe: ([y]) => `y = ${y}`,
  },
};
