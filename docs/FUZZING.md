# Fuzzing

Tests under [test/fuzz](./test/fuzz) use libfuzzer to perform fuzzing tests on crafted targets.

They are enabled by the configure time option `--enable-fuzzing`

## LibFuzzer

LibFuzzer is guided evolutionary fuzzing framework. Information on libfuzzer can be found here:
  - https://llvm.org/docs/LibFuzzer.html

## Running the Fuzz Tests

### Step 1 - Configure Them

As stated before, they are enabled by the configure time option `--enable-fuzzing`. Howevever, often times you
need to also add the following options:
- `--disable-hardning`: Various issues with clang not liking static initializers on complex structs, ie `struct foo x = { 0 };`
- `--disable-overflow`: Clang issues with linking the runtime when __builtin's are used for overflow checking on math.

With clang version 9, I was able to avoid the need for those additional configure options, however, you'll always likely
want `--disable-hardening` to avoid some features that may make debugging harder.

### Step 2 - Running The Fuzz Tests

Running them is as simple as make check.

```sh
make check
```

You should see the normal summary from expected from a make check output.

## Internals

Internally, the tests are organized under the [test/fuzz](./test/fuzz) directory and have a few subdirs:
- [test/fuzz/scripts](./test/fuzz/scripts): Support scripts, like the LOG_COMPILER used as the test runner.
- [test/fuzz](./test/fuzz/corpus): Contains subdirs of corpus bodies used to help guide the fuzzer and
    make it more efficient.

### LOG_COMPILER

LOG_COMPILERS are an automake trick of saying before running the executable that is the test, run this first. It allows one
to also pass options. More can be found [here](https://www.gnu.org/software/automake/manual/html_node/Parallel-Test-Harness.html).
The issue with that, however, is that the granularity is per-file extension. So in this case, we define a `.fuzz` extension that
all executable tests will have, and the [script](test/fuzz/scripts/fuzz-runner.sh) will wrap each execution. We define the options
controlling the run duration and jobs in the script. Using something like `AM_FUZZ_LOG_FLAGS` could also be used, but we would have
to then reorder the command line more to ensure that libfuzzer options apear in front of the fuzz target executable.