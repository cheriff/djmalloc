#ifndef __DJMALLOC_H__
#define __DJMALLOC_H__


#include <stddef.h>

#if !defined(DJMALLOC_NO_TRACKING)
#define djmalloc(x) djmallocInfo(x, (char*)__FILE__, __LINE__)
#define djrealloc(o,n) djreallocInfo(o, n, (char*)__FILE__, __LINE__)
#define djfree(x) djfreeInfo(x, (char*)__FILE__, __LINE__)
#define djstrdup(x) djstrdupInfo(x, (char*)__FILE__, __LINE__)
#define djstrndup(x, n) djstrndupInfo(x, n, (char*)__FILE__, __LINE__)
#define djasprintf(x, ...) djasprintfInfo((char*)__FILE__, __LINE__, x, __VA_ARGS__)
#define djcalloc(cnt, sz) djcallocInfo(cnt, sz, (char*)__FILE__, __LINE__);

void *djmallocInfo(size_t size, char *file, int line);
void *djreallocInfo(void *old, size_t newsize, char *file, int line);
void djfreeInfo(void *ptr, char *file, int line);
char *djstrdupInfo(const char *s, char *file, int line);
char *djstrndupInfo(const char *s, size_t n, char *file, int line);
char *djasprintfInfo(const char *file, int line, const char *fmt, ...);
void *djcallocInfo(size_t count, size_t size, char *file, int line);

#else
#include <stdlib.h>
#define djmalloc(x) malloc(x)
#define djrealloc(o,n) realloc(o, n)
#define djfree(x) free(x)
#define djstrdup(x) strdup(x)
#define djstrndup(x) strndup(x)
#define djasprintf(x, y, ...) asprintf(x, y, __VA_ARGS__)
#define djcalloc(cnt, sz) calloc(cnt, sz)

#endif

void djmalloc_analyze(void);
size_t djheap_snapshot(void);

#if defined (DJMALLOC_IMPLEMENTATION)
#include <stdio.h>
#define UNUSED   __attribute__((unused))
#if !defined(DJMALLOC_NO_TRACKING)

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

typedef struct allocationNode {
    void *ptr;
    const char *file;
    void *caller;
    size_t size;
    int callerCount;
    int line;
    int id;
    int _padding;
} djmallocNode_t;


static int nextID=0;
static size_t outstandingAlloc = 0;
static size_t lifetimeAlloc = 0;
static unsigned int nodeCount = 0;
static djmallocNode_t *nodes = NULL;
#define INITIAL_NODES 50

size_t
djheap_snapshot(void)
{
    return outstandingAlloc;
}

static inline djmallocNode_t *
find_free_node(void)
{
    unsigned int i;
    for(i=0;i<nodeCount; i++) {
        if (nodes[i].ptr == NULL) {
            return &nodes[i];
        }
    }
    
    /* Else none found. Grow the array */
    unsigned int newCount = nodeCount?(nodeCount * 2)
                                      :INITIAL_NODES;
    nodes = realloc(nodes, newCount * sizeof(struct allocationNode));
    assert(nodes && "Cannot alloc new nodeslist for malloc tracking");
    bzero(&nodes[nodeCount],
          (newCount-nodeCount)*sizeof(struct allocationNode));
    
	djmallocNode_t *ret = &nodes[nodeCount];
    nodeCount = newCount;
    return ret;
}

static inline djmallocNode_t *
find_node_for(void *ptr)
{
    unsigned int i;
    for(i=0;i<nodeCount; i++) {
        if (nodes[i].ptr == ptr) {
            return &nodes[i];
        }
    }
    return NULL;
}

static int
count_node_callers(void *caller)
{
    int count = 0;
    unsigned int i;
    for(i=0; i<nodeCount; i++) {
        if (nodes[i].caller == caller) {
            count++;
        }
    }
    return count;
}

static inline void
djmalloc_trackAlloc(void *ptr, size_t size, void *caller, const char *file, int line)
{
    int count = count_node_callers(caller);
    djmallocNode_t *node = find_free_node();
    node->ptr = ptr;
    node->size = size;
    node->caller = caller;
    node->id = nextID++;
    node->file = file;
    node->line = line;
    outstandingAlloc += size;
    node->callerCount = count+1;
    lifetimeAlloc += size;
}

static inline void
djmalloc_trackFree(void *ptr, void *caller UNUSED, char *file, int line)
{
	djmallocNode_t *node = find_node_for(ptr);
    if (!node) {
        printf("Tried to free unalloc'd pointer %p from %s:%d\n",
               ptr, file, line);
        assert(!"Freeing unalloc'd memory");
    }
    
    outstandingAlloc -= node->size;
    bzero(node, sizeof((*node)));
}


char *
djstrdupInfo(const char *s, char *file, int line)
{
    assert(s);
    unsigned int l = (unsigned int)strlen(s) + 1;
    void *caller = __builtin_return_address(0);
    if (l > 1024) {
        printf("Suspicious strdup call: %d byes, from %p",
               l, caller);
    }

    char *ret = malloc(l);
    assert(ret);
    bzero(ret, l);
    djmalloc_trackAlloc(ret, l, caller, file, line);
    memcpy(ret, s, l);

    return ret;
}

char *
djstrndupInfo(const char *s, size_t n, char *file, int line)
{
    assert(s);
    unsigned int l = (unsigned int)strlen(s) + 1;
    void *caller = __builtin_return_address(0);
    if (l > 1024) {
        printf("Suspicious strndup call: %d byes, from %p",
               l, caller);
    }

    char *ret = strndup(s, n);
    assert(ret);
    djmalloc_trackAlloc(ret, l, caller, file, line);

    return ret;
}

char *
djasprintfInfo(const char *file, int line,
        const char *fmt, ...)
{
    assert(fmt);
    char *str;

    void *caller = __builtin_return_address(0);
    va_list args;

    va_start(args, fmt);
    int size = vasprintf(&str, fmt, args);
    assert(size > 0);
    va_end(args);
    
    djmalloc_trackAlloc(str, size, caller, file, line);
    return str;
}

static char * size2str(size_t _b)
{
    unsigned int b = (unsigned int)_b;
    static char words[1024];
    if (b < 1024) {
        sprintf(words, "%2d Bytes", b);
        return words;
    }
    float k = b / 1024.0f;
    
    if (b < 1024*1024) {
        sprintf(words, "%fK (%d bytes)", k, b );
        return words;
    }
    
    float m = b / (1024.0f*1024.0f);
    sprintf(words, "%fM (%d bytes)", m, b);
    return words;
}

void
djmalloc_analyze(void) {
    printf("\n");
    printf("------ DJMALLOC STATS ------\n");
    printf("   Total lifetime allocations: %s\n", size2str(lifetimeAlloc));
    printf("   Remaining heap balance: %s\n", size2str(outstandingAlloc));
    if (outstandingAlloc) {
        printf("   Summary of outstanding allocs:\n");
        unsigned int i;
        int count = 0;
        for(i=0; i<nodeCount; i++) {
            if (nodes[i].ptr) {
                printf("\t%s:%d  - [%p]: Size: %s\tID: %d\tCaller: %p (x%d)\n",
                        nodes[i].file, nodes[i].line,
                        nodes[i].ptr, size2str(nodes[i].size), nodes[i].id, nodes[i].caller, nodes[i].callerCount);
                count++;
            }
        }
        printf("\n%d allocations leaked!\n", count);
        printf("%s bytes leaked\n", size2str(outstandingAlloc));
    }
}

void *
djmallocInfo(size_t size, char *file, int line)
{
    void *ret = malloc(size);
    assert(ret);
    bzero(ret, size);
    djmalloc_trackAlloc(ret, size, __builtin_return_address(0), file, line);
    return ret;
}

void
djfreeInfo(void *ptr, char *file, int line)
{
    if (ptr == NULL) {
        printf("Ignoring NULL free at %s:%d\n", file, line);
        return;
    }
    djmalloc_trackFree(ptr, __builtin_return_address(0), file, line);
    free(ptr);
}

void *
djreallocInfo(void *old, size_t newSize, char *file, int line)
{
    if (old) {
        djmalloc_trackFree(old, __builtin_return_address(0), file, line);
    }
    void *new = realloc(old, newSize);
    assert(new);
    djmalloc_trackAlloc(new, newSize, __builtin_return_address(0), file, line);

    return new;
}

void *
djcallocInfo(size_t num, size_t count, char *file, int line)
{
    void *ret = calloc(num, count);
    assert(ret);
    djmalloc_trackAlloc(ret, num*count, __builtin_return_address(0), file, line);
    return ret;
}


#else // DJMALLOC_NO_TRACKING
size_t djheap_snapshot(void)
{ return 0; }

void djmalloc_analyze(void)
{    printf("DJMalloc-Analyze not available with #DJMALLOC_NO_TRACKING defined\n"); }
#endif // DJMALLOC_NO_TRACKING

#endif // DJMALLOC_IMPLEMENTATION

#if !defined(DJMALLOC_NO_POISON)

void *malloc(size_t)  __attribute__((deprecated("use djmalloc library - djmalloc")));
char *strdup(const char *)  __attribute__((deprecated("use djmalloc library - djstrdup")));
char *strndup(const char *, size_t)  __attribute__((deprecated("use djmalloc library - djstrndup")));

void *calloc(size_t, size_t)  __attribute__((deprecated("use djmalloc library - djcalloc")));
void *realloc(void *, size_t)  __attribute__((deprecated("use djmalloc library - djrealloc")));
int asprintf(char ** __restrict, const char * __restrict, ...)  __attribute__((deprecated("use djmalloc library - djasprintf")));
void free(void *)  __attribute__((deprecated("use djmalloc library - djfree")));

#endif

#endif // __DJMALLOC_H__
