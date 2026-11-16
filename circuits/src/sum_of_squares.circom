pragma circom 2.2.0;

// 8 public inputs + 1 public output: exercises the input-scaling cost of
// vk_x (one ecMul + ecAdd, or one MSM term, per public input).
template SumOfSquares(N) {
    signal input x[N];
    signal output s;
    signal acc[N + 1];
    signal sq[N];
    acc[0] <== 0;
    for (var i = 0; i < N; i++) {
        sq[i] <== x[i] * x[i];
        acc[i + 1] <== acc[i] + sq[i];
    }
    s <== acc[N];
}

component main {public [x]} = SumOfSquares(8);
