#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>

extern int DEBUG_LEVEL;
extern FILE *DEBUG_FILE;

#define __DEBUG_FILE__ DEBUG_FILE

#define __debug__(...) \
    { fprintf(__DEBUG_FILE__, __VA_ARGS__); fflush(__DEBUG_FILE__); }

#define debug(...)				\
    if (DEBUG_LEVEL)				\
	__debug__(__VA_ARGS__);

#define debug2(...)				\
    if (DEBUG_LEVEL >= 2)			\
	__debug__(__VA_ARGS__);

#define debug3(...)				\
  if (DEBUG_LEVEL >= 3)				\
	__debug__(__VA_ARGS__);

#define debug4(...)				\
  if (DEBUG_LEVEL >= 4)				\
	__debug__(__VA_ARGS__);

#endif // __DEBUG_H__

// Local Variables: 
// mode: c++
// End:
