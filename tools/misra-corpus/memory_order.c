/* Memory synchronisation: 21.25.
 *
 * Each guideline has a violating form and a conforming form in this file. */
#include <stdatomic.h>

atomic_int flag;

/* 21.25: a load with a weaker ordering than sequential consistency. */
int read_relaxed_violating(void)
{
    return atomic_load_explicit(&flag, memory_order_relaxed);
}

/* 21.25: a fence with an ordering other than sequential consistency. */
void fence_violating(void)
{
    atomic_thread_fence(memory_order_acquire);
}

/* 21.25, conforming: the plain load, which uses sequential consistency. */
int read_conforming(void)
{
    return atomic_load(&flag);
}

/* 21.25, conforming: the same load with the ordering written out. */
int read_seq_cst_conforming(void)
{
    return atomic_load_explicit(&flag, memory_order_seq_cst);
}
