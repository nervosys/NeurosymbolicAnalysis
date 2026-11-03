/*
 * sda_probe.h - the SDA probe instrumentation, single-header C.
 *
 * The correlation engine needs to know whether a line executed. Without that it
 * cannot tell "this defect did not occur" from "this code never ran", and a
 * coverage hole silently reads as a clean result.
 *
 * On armclang, IAR, TI CGT and anything bare-metal there is no coverage flag and
 * no sanitizer runtime. `sda-build` reports that refusal explicitly and points
 * here. This header is what it points at.
 *
 * Usage:
 *
 *     #define SDA_PROBE_IMPLEMENTATION
 *     #include "sda_probe.h"
 *
 *     int read_sample(const uint8_t *buf, size_t len, size_t i) {
 *         SDA_COV();
 *         if (i >= len) {
 *             SDA_FAULT("bounds", "index past end of buffer");
 *             return 0;
 *         }
 *         return buf[i];
 *     }
 *
 * Define SDA_PROBE_IMPLEMENTATION in exactly one translation unit. Every other
 * unit gets the declarations only.
 *
 * Compiling without SDA_PROBE_ENABLED makes every macro expand to nothing, so a
 * shipping build carries no instrumentation and no runtime cost. Instrument the
 * analysis build, not the product. SDA_CMP_EQ is the one exception, and it has
 * to be: it stands in for a comparison, so compiled out it still evaluates to
 * that comparison's result.
 *
 * To let the fuzzer past a magic value, wrap the comparison that gates the
 * interesting code:
 *
 *     if (SDA_CMP_EQ(magic, 0x5A5A5546uL)) { ... }
 *
 * The operands are reported to the fuzzer, which writes them into later inputs.
 * A process-per-input fuzzer manages tens of runs per second, so a four-byte
 * constant is 2^32 guesses it will never make; told what the program compared
 * against, it reaches the code behind the gate in a handful of runs. Instrument
 * the comparisons that gate things — protocol tags, length fields, magic
 * numbers — not every comparison in a hot loop.
 *
 * ---------------------------------------------------------------------------
 * Freestanding targets - READ THIS BEFORE SHIPPING
 * ---------------------------------------------------------------------------
 * The default sink uses <stdio.h>. Running `sda scan shim/` reports three
 * MISRA C:2023 Rule 21.6 violations against this file for exactly that reason,
 * and they are correct: <stdio.h>, fopen and fwrite have no place in a
 * freestanding build.
 *
 * The default exists so the shim can be exercised on a host during development.
 * On a MISRA-constrained target, define SDA_PROBE_CUSTOM_SINK and provide:
 *
 *     void sda_probe_sink(const char *bytes, unsigned long len);
 *
 * and route it at a UART, an RTT channel, a trace buffer, or a region of RAM the
 * debugger reads after the run. The record format is unchanged, so the engine
 * parses it either way.
 *
 * ---------------------------------------------------------------------------
 * Status
 * ---------------------------------------------------------------------------
 * Compile-tested with MSVC at /W4 /std:c11, and exercised end to end: the
 * records it emits are parsed by the engine and correlated against static
 * findings. Number formatting, including the zero-padding and digit-reversal
 * paths, is checked against expected output. The record format is additionally
 * pinned by the Rust counterpart's test suite (`crates/sda-probe`), which emits
 * the same bytes.
 *
 * The freestanding path has now been run, not merely read. With
 * SDA_PROBE_ENABLED, SDA_PROBE_NO_FLOAT and SDA_PROBE_CUSTOM_SINK, this header
 * builds into a Cortex-M3 image of about 2.2 KB with -nostdlib and no compiler
 * runtime, and that image was executed on an emulated Stellaris LM3S6965 under
 * qemu-system-arm 10.0.11: the records it wrote to the board's UART were
 * captured and correlated by the engine. See examples/firmware-cortex-m/, whose
 * capture is the fixture behind
 * crates/sda-engine/tests/hardware_capture_correlates.rs.
 *
 * That is one target and one toolchain (arm-none-eabi-gcc 14.2.1). Compile it
 * once for yours before relying on it: what the run established is that the path
 * works, not that every toolchain will take it.
 */

#ifndef SDA_PROBE_H
#define SDA_PROBE_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(SDA_PROBE_ENABLED)

/* The numeric type carried by SDA_VALUE and SDA_MARK.
 *
 * Define SDA_PROBE_NO_FLOAT for a build that must not touch floating point at
 * all. It matters more than it looks on a 32-bit MCU: the double path compiles
 * to calls into the compiler runtime — __aeabi_dadd, __aeabi_dmul, __aeabi_d2iz
 * and friends on ARM, __adddf3 and friends on RISC-V — so a freestanding image
 * either links libgcc/compiler-rt or does not link at all, and either way pays
 * several KB of soft-float it never asked for. Linking bare-metal images for
 * Cortex-M4, Cortex-M0 and RISC-V 32 is what exposed this; compiling to objects,
 * which is all this header's checks used to do, cannot see it. */
#if defined(SDA_PROBE_NO_FLOAT)
typedef long sda_probe_num_t;
#else
typedef double sda_probe_num_t;
#endif

void sda_probe_init(void);
void sda_probe_cov(const char *file, unsigned int line);
void sda_probe_fault(const char *file, unsigned int line, const char *kind,
                     const char *message);
void sda_probe_value(const char *file, unsigned int line, const char *key,
                     sda_probe_num_t value);
void sda_probe_mark(const char *key, sda_probe_num_t value);
void sda_probe_cmp(const char *file, unsigned int line, unsigned long lhs,
                   unsigned long rhs);
int sda_probe_cmp_eq_(unsigned long lhs, unsigned long rhs, const char *file,
                      unsigned int line);
void sda_probe_flush(void);

#define SDA_COV() sda_probe_cov(__FILE__, __LINE__)
#define SDA_FAULT(kind, msg) sda_probe_fault(__FILE__, __LINE__, (kind), (msg))
#define SDA_VALUE(key, v)                                                      \
  sda_probe_value(__FILE__, __LINE__, (key), (sda_probe_num_t)(v))
#define SDA_MARK(key, v) sda_probe_mark((key), (sda_probe_num_t)(v))

/* Report the operands of an equality test to the fuzzer, and yield the test's
 * result, so instrumenting a condition does not change what the code does.
 *
 * This is what lets the fuzzer past a magic value. Executing a process per
 * input caps throughput at tens of runs per second, so a four-byte constant is
 * unreachable by brute force; the fuzzer writes observed operands into the
 * input instead. Instrument the comparisons that gate interesting code —
 * protocol tags, length fields, magic numbers — not every comparison in a hot
 * loop, which costs more than it returns.
 *
 * Both operands are evaluated once. */
#define SDA_CMP_EQ(lhs, rhs)                                                   \
  sda_probe_cmp_eq_((unsigned long)(lhs), (unsigned long)(rhs), __FILE__,      \
                    __LINE__)

/* Record a fault when the condition does not hold, and keep going. Unlike
 * assert(), this does not terminate: the point is to collect more, not less. */
#define SDA_CHECK(cond, kind, msg)                                             \
  do {                                                                         \
    if (!(cond)) {                                                             \
      SDA_FAULT((kind), (msg));                                                \
    }                                                                          \
  } while (0)

/* Bounds-check an index. Evaluates its arguments once. */
#define SDA_CHECK_BOUNDS(index, len)                                           \
  SDA_CHECK((unsigned long)(index) < (unsigned long)(len), "bounds",           \
            "index outside container")

#else /* instrumentation compiled out */

/* Compiled out, but still yields the comparison's value: a condition wrapped in
 * SDA_CMP_EQ must behave identically with instrumentation disabled. */
#define SDA_CMP_EQ(lhs, rhs) ((unsigned long)(lhs) == (unsigned long)(rhs))

#define SDA_COV() ((void)0)
#define SDA_FAULT(kind, msg) ((void)0)
#define SDA_VALUE(key, v) ((void)0)
#define SDA_MARK(key, v) ((void)0)
#define SDA_CHECK(cond, kind, msg) ((void)0)
#define SDA_CHECK_BOUNDS(index, len) ((void)0)

#define sda_probe_init() ((void)0)
#define sda_probe_flush() ((void)0)

#endif /* SDA_PROBE_ENABLED */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SDA_PROBE_H */

/* ========================================================================== */
/* Implementation                                                             */
/* ========================================================================== */

#if defined(SDA_PROBE_IMPLEMENTATION) && defined(SDA_PROBE_ENABLED)

#include <stddef.h>

#ifndef SDA_PROBE_CUSTOM_SINK
#include <stdio.h>
#include <stdlib.h>
static FILE *sda_probe_stream_ = NULL;

static void sda_probe_sink(const char *bytes, unsigned long len) {
  if (sda_probe_stream_ == NULL) {
    return;
  }
  (void)fwrite(bytes, 1, (size_t)len, sda_probe_stream_);
  /* Flushed per record on purpose: a fault is usually followed by a crash, and
   * a buffered fault record is a lost one. */
  (void)fflush(sda_probe_stream_);
}
#else
/* Supplied by the integrator. */
void sda_probe_sink(const char *bytes, unsigned long len);
#endif

/* A fixed record buffer: no allocation, so this is usable where malloc is
 * banned (MISRA C:2023 Directive 4.12) and where it does not exist at all. */
#ifndef SDA_PROBE_BUFFER_SIZE
#define SDA_PROBE_BUFFER_SIZE 512u
#endif

static unsigned long sda_probe_strlen_(const char *s) {
  unsigned long n = 0u;
  while ((s != NULL) && (s[n] != '\0')) {
    n++;
  }
  return n;
}

/* Append a JSON-escaped string, truncating rather than overflowing. Mirrors the
 * Rust emitter's `quote` exactly; the two must agree or records become
 * unparseable. */
static unsigned long sda_probe_quote_(char *out, unsigned long cap,
                                      unsigned long at, const char *s) {
  static const char hex[] = "0123456789abcdef";
  unsigned long i = 0u;

  if (at + 1u < cap) {
    out[at] = '"';
    at++;
  }
  for (i = 0u; (s != NULL) && (s[i] != '\0'); i++) {
    unsigned char c = (unsigned char)s[i];
    if ((at + 7u) >= cap) {
      break; /* leave room for the closing quote and terminator */
    }
    switch (c) {
    case '"':
      out[at] = '\\';
      at++;
      out[at] = '"';
      at++;
      break;
    case '\\':
      out[at] = '\\';
      at++;
      out[at] = '\\';
      at++;
      break;
    case '\n':
      out[at] = '\\';
      at++;
      out[at] = 'n';
      at++;
      break;
    case '\r':
      out[at] = '\\';
      at++;
      out[at] = 'r';
      at++;
      break;
    case '\t':
      out[at] = '\\';
      at++;
      out[at] = 't';
      at++;
      break;
    default:
      if (c < 0x20u) {
        out[at] = '\\';
        at++;
        out[at] = 'u';
        at++;
        out[at] = '0';
        at++;
        out[at] = '0';
        at++;
        out[at] = hex[(c >> 4) & 0x0Fu];
        at++;
        out[at] = hex[c & 0x0Fu];
        at++;
      } else {
        out[at] = (char)c;
        at++;
      }
      break;
    }
  }
  if (at + 1u < cap) {
    out[at] = '"';
    at++;
  }
  return at;
}

static unsigned long sda_probe_literal_(char *out, unsigned long cap,
                                        unsigned long at, const char *s) {
  unsigned long i = 0u;
  for (i = 0u; (s[i] != '\0') && ((at + 1u) < cap); i++) {
    out[at] = s[i];
    at++;
  }
  return at;
}

static unsigned long sda_probe_uint_(char *out, unsigned long cap,
                                     unsigned long at, unsigned long v) {
  char digits[24];
  unsigned long n = 0u;
  if (v == 0u) {
    if ((at + 1u) < cap) {
      out[at] = '0';
      at++;
    }
    return at;
  }
#if defined(SDA_PROBE_NO_FLOAT)
  /* Division-free: ARMv6-M (Cortex-M0/M0+) has no divide instruction, so `/ 10`
   * becomes a call to __aeabi_uidiv and a freestanding image that links no
   * compiler runtime fails to link. Repeated subtraction of powers of ten costs
   * at most nine iterations per digit and needs nothing but add and compare. */
  {
    /* Uppercase `L`: MISRA C:2023 Rule 7.3 forbids the lowercase suffix,
     * because `1l` and `11` are hard to tell apart in many fonts. This
     * header's own scan caught it. */
    static const unsigned long p10[10] = {1UL,        10UL,       100UL,
                                          1000UL,     10000UL,    100000UL,
                                          1000000UL,  10000000UL, 100000000UL,
                                          1000000000UL};
    unsigned long i = 10u;
    while (i > 0u) {
      unsigned long d = 0u;
      i--;
      while (v >= p10[i]) {
        v -= p10[i];
        d++;
      }
      if ((d > 0u) || (n > 0u)) {
        if (n < sizeof(digits)) {
          digits[n] = (char)('0' + (char)d);
          n++;
        }
      }
    }
    /* Digits were produced most-significant first; the caller expects the
     * reversed order the division loop below yields, so flip them. */
    {
      unsigned long a = 0u;
      unsigned long b = n;
      while ((b > 0u) && (a < b)) {
        char tmp;
        b--;
        if (a >= b) {
          break;
        }
        tmp = digits[a];
        digits[a] = digits[b];
        digits[b] = tmp;
        a++;
      }
    }
  }
#else
  while ((v > 0u) && (n < sizeof(digits))) {
    digits[n] = (char)('0' + (char)(v % 10u));
    n++;
    v /= 10u;
  }
#endif
  while ((n > 0u) && ((at + 1u) < cap)) {
    n--;
    out[at] = digits[n];
    at++;
  }
  return at;
}

/* Integer-only fixed-point rendering: no floating-point formatting, which many
 * embedded libc builds omit entirely. Three decimals is ample for the metrics
 * this carries. */
static unsigned long sda_probe_number_(char *out, unsigned long cap,
                                       unsigned long at, sda_probe_num_t v) {
#if defined(SDA_PROBE_NO_FLOAT)
  /* No fraction to render, and nothing here touches the compiler's soft-float
   * runtime — the point of the option. */
  if (v < 0) {
    if ((at + 1u) < cap) {
      out[at] = '-';
      at++;
    }
    v = -v;
  }
  return sda_probe_uint_(out, cap, at, (unsigned long)v);
#else
  long whole;
  unsigned long frac;
  double scaled;

  /* JSON has no NaN or Infinity. Emitting one would make the record
   * unparseable, so a non-finite value becomes null. */
  if (!(v == v) || (v > 1.0e308) || (v < -1.0e308)) {
    return sda_probe_literal_(out, cap, at, "null");
  }
  if (v < 0.0) {
    if ((at + 1u) < cap) {
      out[at] = '-';
      at++;
    }
    v = -v;
  }
  whole = (long)v;
  scaled = (v - (double)whole) * 1000.0;
  frac = (unsigned long)(scaled + 0.5);
  if (frac >= 1000u) {
    whole += 1;
    frac = 0u;
  }
  at = sda_probe_uint_(out, cap, at, (unsigned long)whole);
  if (frac != 0u) {
    if ((at + 1u) < cap) {
      out[at] = '.';
      at++;
    }
    /* Pad to three digits so 1.005 does not render as 1.5. */
    if (frac < 100u) {
      at = sda_probe_literal_(out, cap, at, (frac < 10u) ? "00" : "0");
    }
    at = sda_probe_uint_(out, cap, at, frac);
  }
  return at;
#endif
}

static void sda_probe_emit_(char *buf, unsigned long at) {
  if (at + 1u < SDA_PROBE_BUFFER_SIZE) {
    buf[at] = '\n';
    at++;
  }
  sda_probe_sink(buf, at);
}

void sda_probe_init(void) {
#ifndef SDA_PROBE_CUSTOM_SINK
  const char *path = getenv("SDA_PROBE_OUT");
  if ((path != NULL) && (sda_probe_stream_ == NULL)) {
    sda_probe_stream_ = fopen(path, "ab");
  }
#endif
}

void sda_probe_cov(const char *file, unsigned int line) {
  char buf[SDA_PROBE_BUFFER_SIZE];
  unsigned long at = 0u;
  sda_probe_init();
  at = sda_probe_literal_(buf, sizeof(buf), at, "{\"t\":\"cov\",\"f\":");
  at = sda_probe_quote_(buf, sizeof(buf), at, file);
  at = sda_probe_literal_(buf, sizeof(buf), at, ",\"l\":");
  at = sda_probe_uint_(buf, sizeof(buf), at, (unsigned long)line);
  at = sda_probe_literal_(buf, sizeof(buf), at, ",\"n\":1}");
  sda_probe_emit_(buf, at);
}

void sda_probe_fault(const char *file, unsigned int line, const char *kind,
                     const char *message) {
  char buf[SDA_PROBE_BUFFER_SIZE];
  unsigned long at = 0u;
  sda_probe_init();
  at = sda_probe_literal_(buf, sizeof(buf), at, "{\"t\":\"fault\",\"f\":");
  at = sda_probe_quote_(buf, sizeof(buf), at, file);
  at = sda_probe_literal_(buf, sizeof(buf), at, ",\"l\":");
  at = sda_probe_uint_(buf, sizeof(buf), at, (unsigned long)line);
  at = sda_probe_literal_(buf, sizeof(buf), at, ",\"k\":");
  at = sda_probe_quote_(buf, sizeof(buf), at, kind);
  at = sda_probe_literal_(buf, sizeof(buf), at, ",\"m\":");
  at = sda_probe_quote_(buf, sizeof(buf), at, message);
  at = sda_probe_literal_(buf, sizeof(buf), at, "}");
  sda_probe_emit_(buf, at);
}

void sda_probe_value(const char *file, unsigned int line, const char *key,
                     sda_probe_num_t value) {
  char buf[SDA_PROBE_BUFFER_SIZE];
  unsigned long at = 0u;
  sda_probe_init();
  at = sda_probe_literal_(buf, sizeof(buf), at, "{\"t\":\"val\",\"f\":");
  at = sda_probe_quote_(buf, sizeof(buf), at, file);
  at = sda_probe_literal_(buf, sizeof(buf), at, ",\"l\":");
  at = sda_probe_uint_(buf, sizeof(buf), at, (unsigned long)line);
  at = sda_probe_literal_(buf, sizeof(buf), at, ",\"k\":");
  at = sda_probe_quote_(buf, sizeof(buf), at, key);
  at = sda_probe_literal_(buf, sizeof(buf), at, ",\"v\":");
  at = sda_probe_number_(buf, sizeof(buf), at, value);
  at = sda_probe_literal_(buf, sizeof(buf), at, "}");
  sda_probe_emit_(buf, at);
}

void sda_probe_cmp(const char *file, unsigned int line, unsigned long lhs,
                   unsigned long rhs) {
  char buf[SDA_PROBE_BUFFER_SIZE];
  unsigned long at = 0u;
  sda_probe_init();
  at = sda_probe_literal_(buf, sizeof(buf), at, "{\"t\":\"cmp\",\"f\":");
  at = sda_probe_quote_(buf, sizeof(buf), at, file);
  at = sda_probe_literal_(buf, sizeof(buf), at, ",\"l\":");
  at = sda_probe_uint_(buf, sizeof(buf), at, (unsigned long)line);
  at = sda_probe_literal_(buf, sizeof(buf), at, ",\"a\":");
  at = sda_probe_uint_(buf, sizeof(buf), at, lhs);
  at = sda_probe_literal_(buf, sizeof(buf), at, ",\"b\":");
  at = sda_probe_uint_(buf, sizeof(buf), at, rhs);
  at = sda_probe_literal_(buf, sizeof(buf), at, "}");
  sda_probe_emit_(buf, at);
}

/* Behind SDA_CMP_EQ so the macro can evaluate each operand exactly once and
 * still yield the comparison's result. */
int sda_probe_cmp_eq_(unsigned long lhs, unsigned long rhs, const char *file,
                      unsigned int line) {
  sda_probe_cmp(file, line, lhs, rhs);
  return (lhs == rhs) ? 1 : 0;
}

void sda_probe_mark(const char *key, sda_probe_num_t value) {
  char buf[SDA_PROBE_BUFFER_SIZE];
  unsigned long at = 0u;
  sda_probe_init();
  at = sda_probe_literal_(buf, sizeof(buf), at, "{\"t\":\"mark\",\"k\":");
  at = sda_probe_quote_(buf, sizeof(buf), at, key);
  at = sda_probe_literal_(buf, sizeof(buf), at, ",\"v\":");
  at = sda_probe_number_(buf, sizeof(buf), at, value);
  at = sda_probe_literal_(buf, sizeof(buf), at, "}");
  sda_probe_emit_(buf, at);
}

void sda_probe_flush(void) {
  /* Records are written through, so there is nothing pending. Provided so the
   * C and Rust APIs have the same shape. */
  (void)sda_probe_strlen_;
#ifndef SDA_PROBE_CUSTOM_SINK
  if (sda_probe_stream_ != NULL) {
    (void)fflush(sda_probe_stream_);
  }
#endif
}

#endif /* SDA_PROBE_IMPLEMENTATION && SDA_PROBE_ENABLED */

