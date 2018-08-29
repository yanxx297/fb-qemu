#ifndef __SYMBOLIC__
#define __SYMBOLIC__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef KLEE
#include <klee/klee.h>
#endif
#include <assert.h>

#ifdef DECLARE_GLOBALS
char symbolic_execution = 0;
#endif
extern char symbolic_execution;

void *ADDRESS_HERE();

static inline void *tls() {
  void *gs;
  __asm__ volatile("mov %%gs:0x0, %0;" : "=r"(gs));
  return gs;
}

#if defined(KLEE) || defined(FUZZBALL)

#define SYMBOLIC_EXECUTION

// *****************************************************************************
// KLEE
// *****************************************************************************
#if defined(KLEE)

#define IGNORE(p) 

#define ASSUME_EQ(a, b)				\
  klee_assume((a) = (b))

#define ASSUME_EQ_masked(a, b, c)		\
  klee_assume((a) & c = (b) & c)

#define IS_SYMBOLIC(x) \
  klee_is_symbolic(x)

#define MAKE_SYMBOLIC(a, t, l, n)		\
  klee_make_symbolic(t, l, n)

#define INIT_SYMBOLIC_EXECUTION()		\
  symbolic_execution = 1

#define START_SYMBOLIC_EXECUTION(p)

#define TERMINATE_SYMBOLIC_EXECUTION(p)

#define __concretize_helper_template(s, t)	\
  static inline t __concretize_helper(t v) {	\
    return (t) klee_get_value##s(v);		\
  }

#define MAKE_CONCRETE(a, e, v) 

// *****************************************************************************
// FUZZBALL 
// *****************************************************************************
#elif defined(FUZZBALL)

#ifdef DECLARE_GLOBALS
char fuzzball_dryrun = 0;
#endif

extern char fuzzball_dryrun;

#define FUZZBALL_DRYRUN (fuzzball_dryrun == 1)

void fuzzball_ignore_path(const char *c) {
  if (!fuzzball_dryrun) {
    exit(0);
  }
}

void fuzzball_terminate_execution(void *p) {
  if (fuzzball_dryrun) {
    printf("FUZZBALL_STOP_ADDRESS\t%p\n", p);
  }
}

void fuzzball_start_tracing() {
  if (fuzzball_dryrun) {
    printf("FUZZBALL_START_TRACING\t%p\n", fuzzball_start_tracing);
  }
}

void fuzzball_start_execution(void *p) {
  // printf("FUZZBALL_START_ADDRESS\t%p\n", p);
  if (fuzzball_dryrun)
    printf("FUZZBALL_START_ADDRESS\t%p\n", (void *) fuzzball_start_execution);
}

void fuzzball_ignore_pathcond_till_here() {
  if (fuzzball_dryrun)
    printf("FUZZBALL_IGNORE_PATHCOND_TILL\t%p\n", (void *) fuzzball_ignore_pathcond_till_here);
}

void fuzzball_gen_coredump() {
  if (fuzzball_dryrun)
    printf("FUZZBALL_COREDUMP_ADDRESS\t%p\n", (void *) fuzzball_gen_coredump);
}

// This is a very dirty hack. We output the expression representing the
// condition and later (from the python script) we translate memory addresses
// to symbolic variables
static void inline fuzzball_assert_eq(void *addr, unsigned char val, unsigned char mask) {
  if (fuzzball_dryrun)
    printf("FUZZBALL_ASSERT_EQ\t%p\t0x%.2x\t0x%.2x\n", addr, mask, val & mask);
}

#define ASSUME_EQ(a, b)			\
  if (fuzzball_dryrun)			\
    fuzzball_assert_eq(&(a), b, 0xff)

#define ASSUME_EQ_masked(a, b, c)	\
  if (fuzzball_dryrun)			\
    fuzzball_assert_eq(&(a), b, c)

#define IGNORE(p)				\
  if (!(p))					\
    fuzzball_ignore_path(#p)

#define IS_SYMBOLIC(x) \
  (1)

static inline void fuzzball_make_symbolic(void *v, size_t s, const char *n) {
  if (fuzzball_dryrun) {
    printf("FUZZBALL_SYMBOLIC_VARIABLE\t%p\t%u\t%s\n", v, s, n);
  }
}

#define MAKE_SYMBOLIC(a, t, l, n)		\
  fuzzball_make_symbolic(a, l, n)

#define MAKE_CONCRETE(a, e, v)					\
  if (fuzzball_dryrun) {					\
    printf("FUZZBALL_CONCRETIZE_VARIABLE\t%p\t%s\t%s\n", a, e, v);	\
  }

#define INIT_SYMBOLIC_EXECUTION()					\
  symbolic_execution = getenv("FUZZBALL_EXECUTION") ? 1 : 0;		\
  fuzzball_dryrun = getenv("FUZZBALL_DRY_RUN") ? 1 : 0;			\
  if (fuzzball_dryrun) {						\
    printf("FUZZBALL_IGNORE_PATH_THROUGH\t%p\n", fuzzball_ignore_path); \
  }									\

#define TERMINATE_SYMBOLIC_EXECUTION(p) \
  fuzzball_terminate_execution((void *) p)

#define __concretize_helper_template(s, t)	\
  static inline t __concretize_helper(t v) {	\
    return (t) 0;				\
  }

#endif // !FUZZBALL

#define IS_CONCRETE(x) \
  (!IS_SYMBOLIC(x))

#define START_SYMBOLIC_EXECUTION(p)		\
  fuzzball_gen_coredump();			\
  fuzzball_start_execution((void *)p );		

#define IGNORE_PATHCOND_TILL_HERE()		\
  fuzzball_ignore_pathcond_till_here();		

#define START_TRACING() \
  fuzzball_start_tracing();

#define FINI_SYMBOLIC_EXECTUION() \
  if (fuzzball_dryrun)		  \
    exit(0);

// *****************************************************************************
// Make variable concrete
// *****************************************************************************
__concretize_helper_template(f, float);
__concretize_helper_template(d, double);
__concretize_helper_template(l, long);
__concretize_helper_template(ll, long long);
__concretize_helper_template(_i32, int32_t);
__concretize_helper_template(_i32, unsigned int);
__concretize_helper_template(_i32, unsigned char);

#undef __concretize_helper_template

template<typename V>
static inline V __concretize(V v) {
  if (IS_SYMBOLIC(v)) {
    return __concretize_helper(v);
  } else {
    return v;
  }
}

static inline void __concretize(void *a, size_t s) {
  size_t j;
  unsigned char *b = (unsigned char *) a;

  for (j = 0; j < s; j++) {
    b[j] = __concretize(b[j]);
  }
}

#define CONCRETE_VALUE(x) \
  __concretize(x)

#else // !SYMBOLIC_EXECUTION

#define IGNORE(p)

#define MAKE_SYMBOLIC(a, t, l, n)

#define CONCRETE_VALUE(x) x

#define INIT_SYMBOLIC_EXECUTION()

#define START_SYMBOLIC_EXECUTION(p)

#define TERMINATE_SYMBOLIC_EXECUTION(p)

#define IS_SYMBOLIC(x) 0

#define IS_CONCRETE(x) 1

#define ASSUME_EQ(a, b)

#define ASSUME_EQ_masked(a, b, c)

#define MAKE_CONCRETE(a, e, v)

#define START_TRACING()

#define FINI_SYMBOLIC_EXECTUION()

#endif // SYMBOLIC_EXECUTION

#if 0
// Dirty hack
template<typename V>
static inline V __random(V v) {
  V r = random() % 0x400000;
  printf("Concretizing value --> 0x%x\n", r);
  return r; 
}

#define MAKE_CONCRETE(x)	 \
  printf("Concretizing %d\n", symbolic_execution); \
  if (symbolic_execution) {	 \
    x = __random(x);		 \
  }

#endif

#endif // !__SYMBOLIC__

// Local Variables: 
// mode: c++
// End:
