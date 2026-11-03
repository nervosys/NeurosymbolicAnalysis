// MISRA C++:2023 constructs with a clang-tidy check behind them.
//
// Twenty-one C++ guidelines are classified `native` in this catalogue and none
// had ever been compared with anything. These are the ones clang-tidy's
// cppcoreguidelines module decides too, so the two can be held to each other.
//
// Deliberately defective; `tools` is out of the delivered product.
#include <cstdlib>

// 8.2.1: a C-style cast.
int truncate_it(long v) {
  return (int)v;
}

// 8.2.2: reinterpret_cast.
unsigned char first_byte(const long* p) {
  return *reinterpret_cast<const unsigned char*>(p);
}

// 8.2.3: const_cast removing const.
void writes_through(const int* p) {
  int* q = const_cast<int*>(p);
  *q = 1;
}

// 21.6.1: dynamic allocation.
int* make(unsigned long n) {
  return static_cast<int*>(std::malloc(n * sizeof(int)));
}

void unmake(int* p) {
  std::free(p);
}

// 9.6.1: goto.
int retry(int n) {
  int tries = 0;
again:
  tries++;
  if (tries < n) {
    goto again;
  }
  return tries;
}
