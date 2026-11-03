// MISRA C++:2023 9.4.1, 9.4.2, 9.4.3 and 21.10.1.
//
// Three of these are compiler warnings rather than clang-tidy checks, which
// clang-tidy surfaces under `clang-diagnostic-*`. That matters: it means the
// second implementation for them is the compiler, not a linter's opinion.
#include <csetjmp>

extern void act(int v);

// 9.4.1: the body of a selection statement is not a compound statement.
int unbraced(int n) {
  if (n > 0)
    return 1;
  return 0;
}

// 9.4.2: a switch-clause with no unconditional break falls through.
// 9.4.3: and the switch has no default label.
int falls_through(int v) {
  int out = 0;
  switch (v) {
  case 1:
    out = 1;
  case 2:
    out = 2;
    break;
  }
  return out;
}

// 21.10.1: the features of <csetjmp>.
static std::jmp_buf env;

void bail() {
  std::longjmp(env, 1);
}
