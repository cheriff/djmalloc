# djmalloc
Yet another debugging malloc. Singlefile.
Currently only really tested on macos.

## Useage

Include djmalloc.h in your project. Exactly one .c file should define `DJMALLOC_IMPLEMENTATION` beforehand.

Then, use wrapped functions instead of the standard equivalents:

* void *djmalloc(size_t size);
* void *djrealloc(void *old, size_t newsize);
* void djfree(void *ptr);
* char *djstrdup(const char *s);
* char *djasprintf(const char *fmt, ...);
* void *djcalloc(size_t count, size_t size);

The current outstanding heap allocations may be obtained. This will list the total lifetime allocations made, as well as any outstanding
"leaks". For each not-yet-free'd allocation, the size and call site is provided.
* size_t djheap_snapshot(void);

And a summary may be printed:
* void djmalloc_analyze(void);

## Overhead
Tracking size and call sites of individual allocations incurs time and memory overhead. This can be avoided by defining `DJMALLOC_NO_TRACKING`.
In this case the dj-functions are defined to be the standard variants, and leak-checking ability is lost.

## Posioning
Unless `DMALLOC_NO_POISON` is defined, then the standard functions (malloc, realloc, free, strdup, asprintf, calloc) will be marked deprecated. This should result in compiler warning if the non-dj variants are accidentally used.

# Example

Example usage:

```
#define DJMALLOC_IMPLEMENTATION
#include "djmalloc.h"

#include <stdio.h>·

int main(void)
{
    void *whoops= malloc(12); // should warn, as vanilla 'malloc' is posioned.

    size_t before = djheap_snapshot();
    void *a = djmalloc(12);
    a = djrealloc(a, 36);
    
    djfree(a);

    size_t after = djheap_snapshot();
    printf("Outsanding heap: %ld\n", after-before);
    if (after - before) {
        djmalloc_analyze();
    }

    return after;
}
```

Compile:
```
$ gcc test.c -o test
test.c:13:19: warning: 'malloc' is deprecated: use djmalloc library - djmalloc [-Wdeprecated-declarations]
    void *whoops= malloc(12);
 ```
 
 And run:
 
 ```
 $ ./test
Outstanding heap: 0
```

Or, if we forgot to djfree on line 13:

```
$ ./test
Outstanding heap: 36

------ DJMALLOC STATS ------
   Total lifetime allocations: 48 Bytes
   Remaining heap balance: 36 Bytes
   Summary of outstanding allocs:
	test.c:12  - [0x7fea2ec027a0]: Size: 36 Bytes	ID: 1	Caller: 0x1034e8970 (x1)

1 allocations leaked!
36 Bytes bytes leaked
```

# Loops
If the same line leaks multiple times, then each instance is indivudially reported:

```
12   void *first = djmalloc(99);
13
14   for (i=0; i<15; i++) {
15        void *leak = djmalloc(12);
16    }
17    djmalloc_analyze();
  
Prints:
------ DJMALLOC STATS ------
   Total lifetime allocations: 159 Bytes
   Remaining heap balance: 159 Bytes
   Summary of outstanding allocs:
	test.c:12  - [0x7fa140502620]: Size: 99 Bytes	ID: 0	Caller: 0x109f9c930 (x1)
	test.c:15  - [0x7fa140502690]: Size: 12 Bytes	ID: 1	Caller: 0x109f9c95d (x1)
	test.c:15  - [0x7fa1405026a0]: Size: 12 Bytes	ID: 2	Caller: 0x109f9c95d (x2)
	test.c:15  - [0x7fa1405026b0]: Size: 12 Bytes	ID: 3	Caller: 0x109f9c95d (x3)
	test.c:15  - [0x7fa1405026c0]: Size: 12 Bytes	ID: 4	Caller: 0x109f9c95d (x4)
	test.c:15  - [0x7fa1405026d0]: Size: 12 Bytes	ID: 5	Caller: 0x109f9c95d (x5)
```
We can see the global allocation id incrementing, as well as the per-callsite count within the loop.
These can help breakpoint setting when tracking down a specific leak.

# Double-Free
Extraneous frees cause panics, and NULL-frees are warned upon, but otherwise allowed

```
8      void *lol = 0;
9      djfree(lol);
10
11     void *allocated = djmalloc(101);
12     djfree(allocated);
13     djfree(allocated);
14
15     int  not_allocated[12] = {0};
16     djfree(not_allocated);
 
 Results in runtime output:
 
 Ignoring NULL free at test.c:9
 Tried to free unalloc'd pointer 0x7ff5504027a0 from test.c:13
 Assertion failed: (!"Freeing unalloc'd memory"), function djmalloc_trackFree, file ./djmalloc.h, line 142.
 ```
 The non-allocated free on line 16 would also have asserted had it been reached.
