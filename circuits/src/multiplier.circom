pragma circom 2.2.0;

// Knowledge of a non-trivial factorization: c = a * b with a, b != 1.
template Multiplier() {
    signal input a;
    signal input b;
    signal output c;

    // a != 1 and b != 1  (x - 1 must be invertible)
    signal inva;
    signal invb;
    inva <-- 1 / (a - 1);
    invb <-- 1 / (b - 1);
    (a - 1) * inva === 1;
    (b - 1) * invb === 1;

    c <== a * b;
}

component main = Multiplier();
