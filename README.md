# eBPF Unit Test

Demo Repository for eBPF XDP Unit Test

- Compile using:
```
clang -O2 -target bpf -c allow_ssh.c -o allow_ssh.o
```

- Generate a Skeleton file:
```
bpftool gen skeleton allow_ssh.o > allow_ssh.skel.h
```

- Compile the tests:
```
gcc -o test test.c -lbpf
```
**Note**: `-lbpf` links the program to the libbpf library, which is a user-space library that provides APIs to interact with eBPF programs.
