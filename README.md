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

The current outstanding heap allocations may be obtained:
* size_t djheap_snapshot(void);

And a summary may be printed:
* void djmalloc_analyze(void);

## Overhead
Tracking allocations incurs time and memory overhead. This can be avoided by defining `DJMALLOC_NO_TRACKING`.
In this case the dj-functions are defined to be the standard variants.

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

