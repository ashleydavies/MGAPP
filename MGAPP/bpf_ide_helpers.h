#ifndef BPF_IDE_HELPERS_H
#define BPF_IDE_HELPERS_H

// This file should _NOT_ be imported for real.
// It can be "#include"d to make an IDE 'understand' BPF code to be able to lint and format it somewhat correctly.
// This include should be removed before the code is passed to the preprocessor!

#define TRACEPOINT_PROBE(A, B) static int ##A_##B()
#define u32 int
#define u64 long long int
#define BPF_ARRAY(A, B, C)
#define BPF_PERCPU_ARRAY(A, B, C)
#define BPF_HASH(A, B, C, D)
#define BPF_STACK_TRACE(A, B)
#define FILTER ;

#endif
