// MISRA C++:2023 19.0.1, 19.6.1 and 12.2.1.
//
// A header on purpose: 19.6.1 is about include guards, which only a header can
// lack. There is deliberately no guard here.

// 19.0.1: a function-like macro where a function or template would serve.
#define SQUARE(x) ((x) * (x))

// 12.2.1: a union.
union Word {
  unsigned long whole;
  unsigned char bytes[8];
};

inline unsigned char low_byte(Word w) {
  // Reading a member other than the one last written is the part clang-tidy
  // objects to; the declaration above is the part MISRA objects to.
  return w.bytes[0];
}

inline int squared(int v) {
  return SQUARE(v);
}
