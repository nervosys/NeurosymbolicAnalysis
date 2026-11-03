/* A freestanding Cortex-M3 image that runs, and reports what it did.
 *
 * `examples/firmware/` is a project with deliberate MISRA violations and a
 * `fake_instrumented.bat` that *writes probe records by hand*. This is the same
 * idea with the simulation taken out: a real image, linked with -nostdlib and no
 * compiler runtime, executed on an emulated Stellaris LM3S6965 (Cortex-M3),
 * emitting the shim's records through the board's UART. What comes back is a
 * capture, not a fixture.
 *
 * Build and run: see README.md in this directory.
 *
 * The program is written so the run produces something to correlate rather than
 * a wall of coverage:
 *
 *   * `decode` is called with inputs that reach the bounds check and trip it, so
 *     the capture carries a real `bounds` fault at a line a static rule also has
 *     an opinion about.
 *   * `recovery` is never called. Its lines therefore appear in no coverage
 *     record, which is what lets the engine say *unreached* rather than *clean*
 *     — the distinction the whole toolkit is about.
 *   * `checksum` runs to completion without faulting, so a finding about it is
 *     answered by evidence rather than by silence.
 */

#include <stddef.h>
#include <stdint.h>

#define SDA_PROBE_IMPLEMENTATION
#include "sda_probe.h"

/* Laid out by `link.ld`. Declared here because the stack measurement below
 * needs them, and it sits above the startup code that also does. */
extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;

/* --- the board -----------------------------------------------------------
 *
 * Stellaris LM3S6965, as QEMU models it. UART0 is wired to the character
 * device, so anything written to the data register arrives on stdout.
 */
#define UART0_BASE 0x4000C000u
#define UART0_DR (*(volatile uint32_t *)(UART0_BASE + 0x000u))
#define UART0_FR (*(volatile uint32_t *)(UART0_BASE + 0x018u))
#define UART_FR_TXFF (1u << 5)

/* The sink the shim calls. Declared by sda_probe.h under
 * SDA_PROBE_CUSTOM_SINK, which is what makes the freestanding path real: no
 * stdio, no fopen, no allocation anywhere in this image. */
void sda_probe_sink(const char *bytes, unsigned long len) {
  unsigned long i;
  for (i = 0u; i < len; i++) {
    while ((UART0_FR & UART_FR_TXFF) != 0u) {
      /* wait for room in the transmit FIFO */
    }
    UART0_DR = (uint32_t)(unsigned char)bytes[i];
  }
}

/* --- the program ---------------------------------------------------------- */

static uint8_t buffer[8];

/* Decode one field out of a frame. The bounds check fires for the last call. */
static int decode(const uint8_t *frame, size_t len, size_t index) {
  SDA_COV();
  if (index >= len) {
    SDA_FAULT("bounds", "field index past the end of the frame");
    return -1;
  }
  SDA_COV();
  return (int)frame[index];
}

/* Sum a frame. Runs to completion on every call, and says so. */
static int checksum(const uint8_t *frame, size_t len) {
  size_t i;
  int total = 0;
  SDA_COV();
  for (i = 0u; i < len; i++) {
    total += (int)frame[i];
  }
  SDA_VALUE("checksum", total);
  return total;
}

/* Never called. That is the point: its lines must come back *unreached*, not
 * clean, and nothing in the capture should suggest otherwise. */
static void recovery(void) {
  SDA_COV();
  SDA_FAULT("stack", "recovery path entered");
}

/* --- stack measurement ---------------------------------------------------
 *
 * `SDA_MARK("stack_bytes", 1024)` used to report a number the program had been
 * told. It was never measured, and on a part where the stack grows into the
 * heap or into `.bss` that is the difference between a margin and an accident —
 * exactly the kind of claim this toolkit exists to stop being made.
 *
 * Measured the way embedded systems have always measured it: fill the unused
 * stack with a pattern before `main`, then find the lowest address still
 * holding it. The result is a high-water mark for the whole run, not a sample.
 *
 * It is still not a claim about silicon. Interrupt frames pushed by a real
 * NVIC, a deeper vendor startup path and a compiler at a different optimisation
 * level all move this number. What it now reports is what *this* image did on
 * this machine, which is a measurement rather than a belief.
 */
#define STACK_PATTERN 0xC0DEC0DEu

/* The painter's own frame must survive being painted over. Thirty-two bytes is
 * far more than the loop below needs and costs only that much precision. */
#define STACK_PAINT_MARGIN 32u

static void paint_stack(void) {
  uint32_t here = 0u; /* an object on the current frame, for its address */
  uint32_t *p = &_ebss;
  uint32_t *limit = (uint32_t *)(((uintptr_t)&here - STACK_PAINT_MARGIN) & ~3u);

  while (p < limit) {
    *p = STACK_PATTERN;
    p++;
  }
}

static uint32_t stack_used_bytes(void) {
  const uint32_t *p = &_ebss;

  while (p < &_estack && *p == STACK_PATTERN) {
    p++;
  }
  return (uint32_t)((uintptr_t)&_estack - (uintptr_t)p);
}

int main(void) {
  size_t i;
  int v;

  sda_probe_init();

  for (i = 0u; i < sizeof(buffer); i++) {
    buffer[i] = (uint8_t)(i * 3u);
  }

  (void)checksum(buffer, sizeof(buffer));

  /* Three in range, one past the end. */
  v = decode(buffer, sizeof(buffer), 0u);
  v += decode(buffer, sizeof(buffer), 4u);
  v += decode(buffer, sizeof(buffer), 7u);
  v += decode(buffer, sizeof(buffer), 9u);
  SDA_VALUE("decoded", v);

  if (0) {
    recovery(); /* referenced so it links, never executed */
  }

  /* Reported here rather than at entry: at entry nothing has been used yet, so
   * the number would have been a prediction either way. */
  SDA_MARK("stack_bytes", stack_used_bytes());

  sda_probe_flush();

  /* Tell the emulator to stop, through ARM semihosting: without this QEMU runs
   * until something kills it, and a harness that depends on a timeout cannot
   * tell a finished run from a hung one. */
  {
    register uint32_t r0 __asm__("r0") = 0x18u;      /* SYS_EXIT */
    register uint32_t r1 __asm__("r1") = 0x20026u;   /* ADP_Stopped_ApplicationExit */
    __asm__ volatile("bkpt #0xAB" : : "r"(r0), "r"(r1) : "memory");
  }
  for (;;) {
  }
}

/* --- startup --------------------------------------------------------------
 *
 * No C runtime, so .data and .bss are ours to set up. The vector table has to
 * be first in flash: the core loads the initial stack pointer from word 0 and
 * the reset vector from word 1 before any of our code runs.
 */

void Reset_Handler(void);
static void Default_Handler(void);

__attribute__((section(".isr_vector"), used)) void *const vector_table[] = {
    (void *)&_estack,   /* initial SP  */
    (void *)Reset_Handler, /* reset    */
    (void *)Default_Handler, /* NMI    */
    (void *)Default_Handler, /* HardFault */
};

static void Default_Handler(void) {
  for (;;) {
  }
}

void Reset_Handler(void) {
  uint32_t *src = &_sidata;
  uint32_t *dst = &_sdata;

  while (dst < &_edata) {
    *dst = *src;
    dst++;
    src++;
  }
  for (dst = &_sbss; dst < &_ebss; dst++) {
    *dst = 0u;
  }

  /* After `.bss` is zeroed — painting first would be undone — and before any of
   * the program runs, so the high-water mark covers all of it. */
  paint_stack();

  (void)main();
  for (;;) {
  }
}
