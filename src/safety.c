#include <string.h>
#include <pthread.h>

#include "config.h"

#include <libiberty/demangle.h>

#ifdef USE_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#else
#include <execinfo.h>
#endif


#define PAGE_SIZE		4096
#define CHUNK_SIZE(x)		(x+4)

#define MAX_FREE_CHUNKS_PER_PAGE		((PAGE_SIZE - sizeof(safe_free_chunk_list_t)) / sizeof(void *))
#define CEIL(x,y)				(((x) + (y) - 1) / (y))
//#define CTRL_PAGES_PER_BUCKET(ratio,sz)		((((PAGE_PREALLOC_SIZE / ratio ) * (PAGE_SIZE / sz))) / MAX_FREE_CHUNKS_PER_PAGE)
#define CTRL_PAGES_PER_BUCKET(ratio,sz)		(CEIL((((PAGE_PREALLOC_SIZE / ratio ) * (PAGE_SIZE / sz))), MAX_FREE_CHUNKS_PER_PAGE))
#define TOTAL_CHUNKS(ratio,sz)			((PAGE_PREALLOC_SIZE / ratio) * (PAGE_SIZE / sz))


static int _bucket_init = 0;

typedef struct safe_free_chunk_list {
	struct safe_free_chunk_list *next;
	struct safe_free_chunk_list *prev;
	void *free_chunks[0];
} __attribute__((packed)) safe_free_chunk_list_t;

#define CHUNK_FLAG_DIRECT_MAP	1

typedef struct safe_chunk_hdr {
	unsigned int size:24;
	unsigned int flags:8;
} __attribute__((packed)) safe_chunk_hdr_t;



/*
 * Buckets:
 * 1. 16:    256 per page
 * 2. 32:    128 per page
 * 3. 64:    64  per page
 * 4. 128:   32  per page
 * 5. 256:   16  per page
 * 6. 512:   8   per page
 * 7. 1024:  4   per page
 * 8. 2048:  2   per page
 * 9. 4096+: 1-  per page
 */

#define N_CHUNK_BUCKETS		9
// Optimize default bucket allocation for latrace's allocation of small strings/data structs
#define CHUNK_BUCKET_1_RATIO	4  // (1/4)
#define CHUNK_BUCKET_2_RATIO	2  // (1/2)
#define CHUNK_BUCKET_3_RATIO	32 // (1/32)
#define CHUNK_BUCKET_4_RATIO	32
#define CHUNK_BUCKET_5_RATIO	32
#define CHUNK_BUCKET_6_RATIO	32
#define CHUNK_BUCKET_7_RATIO	32
#define CHUNK_BUCKET_8_RATIO	32
// Bucket is the remainder

// Preallocate 4MB
#define PAGE_PREALLOC_SIZE	1024

static safe_free_chunk_list_t *free_chunk_buckets[N_CHUNK_BUCKETS];
static pthread_mutex_t bucket_locks[N_CHUNK_BUCKETS];


int glibc_unsafe = 0;


inline void *
xxmalloc(size_t size) {
	return malloc(size);
}

inline void *
xxrealloc(void *ptr, size_t size) {
	return realloc(ptr, size);
}

inline char *
xxstrdup(const char *s) {
	return strdup(s);
}


void *
_allocate_pages(size_t n) {
	void *result;

	if ((result = mmap(NULL, (PAGE_SIZE*n), PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		return NULL;

	return result;
}

int
_add_bucket_free_chunk(safe_free_chunk_list_t *flist, safe_chunk_hdr_t *chunk) {
	safe_free_chunk_list_t *fnew;
	ssize_t i;

	/* Seek to the very last chunk */
	while (flist->next)
		flist = flist->next;

	/* If we're full we need a new control page */
	if (flist->free_chunks[MAX_FREE_CHUNKS_PER_PAGE-1]) {
		fnew = _allocate_pages(1);
		if (!fnew)
			return -1;

		memset(fnew, 0, PAGE_SIZE);
		fnew->prev = flist;
		flist->next = fnew;
		fnew->free_chunks[0] = chunk;
		fnew->free_chunks[1] = NULL;
		return 0;
	}

	/* And then find the last used chunk going backwards */
	for (i = MAX_FREE_CHUNKS_PER_PAGE-2; i >= 0; i--) {

		if (flist->free_chunks[i]) {
			// There's still room, add it to this page.
			flist->free_chunks[i+1] = chunk;
			break;
		}

	}

	return 0;
}

void *
_get_bucket_free_chunk(safe_free_chunk_list_t *flist) {
	void *result = NULL;
	safe_free_chunk_list_t *prevlist = NULL;
	ssize_t i;

	/* Seek to the very last chunk */
	while (flist->next) {
		prevlist = flist;
		flist = flist->next;
	}

	/* And then find the last used chunk going backwards */
	for (i = MAX_FREE_CHUNKS_PER_PAGE-1; i >= 0; i--) {

		if (flist->free_chunks[i]) {
			result = flist->free_chunks[i];
			flist->free_chunks[i] = NULL;
			break;
		}

	}

	/* If we hit the end, we need to unlink this control page */
	// XXX: Here lies a memory leak.
	// XXX: We need to toss this page into the free 4096 (page-sized) free list.
	if ((i == 0) && prevlist)
		prevlist->next = NULL;

	return result;
}

size_t
_get_bucket_by_reqsize(size_t nbytes) {
	size_t i;
	size_t real_size = nbytes + sizeof(safe_chunk_hdr_t);

	for (i = 0; i < N_CHUNK_BUCKETS; i++) {
		size_t bucket_max = (16 << i);

		if (real_size <= bucket_max)
			return i;

	}

	return N_CHUNK_BUCKETS;
}

void
_dump_all_buckets(void) {
	size_t b;

	fprintf(stderr, "Looking through: %d buckets\n", N_CHUNK_BUCKETS);

	for (b = 0; b < N_CHUNK_BUCKETS; b++) {
		safe_free_chunk_list_t *head, *fptr;
		size_t count = 0, entries = 0;

		fprintf(stderr, "B %.4d: %p\n", (16 << b), free_chunk_buckets[b]);

		fptr = head = free_chunk_buckets[b];
		fprintf(stderr, "FIRST: %p, ", head->free_chunks[0]);

		while (fptr) {
			size_t i;

			count++;

			for (i = 0; i < MAX_FREE_CHUNKS_PER_PAGE; i++) {

				if (!fptr->free_chunks[i]) {
					fprintf(stderr, "last: %p\n", fptr->free_chunks[i-1]);
					break;
				}

				entries++;
			}

			if (i != MAX_FREE_CHUNKS_PER_PAGE)
				break;

			fptr = fptr->next;
		}

		fprintf(stderr, "   total ctrl pages = %zu; entries = %zu\n", count, entries);
	}

	return;
}

int
_carve_chunks(safe_free_chunk_list_t *head, size_t chunk_size, size_t total_chunks, safe_free_chunk_list_t **next_ptr) {
	unsigned char *freeptr;
	size_t n_ctrl_pages, n, p, entries = 0;

	n_ctrl_pages = CEIL(total_chunks, MAX_FREE_CHUNKS_PER_PAGE);
	freeptr = ((unsigned char *)head) + (n_ctrl_pages * PAGE_SIZE);

	head->prev = NULL;

	for (p = 0; p < n_ctrl_pages; p++) {
		safe_free_chunk_list_t *pfree = (safe_free_chunk_list_t *)((unsigned char *)head + (PAGE_SIZE * (p-1)));
		safe_free_chunk_list_t *nfree = (safe_free_chunk_list_t *)((unsigned char *)head + (PAGE_SIZE * (p+1)));
		safe_free_chunk_list_t *tfree = (safe_free_chunk_list_t *)((unsigned char *)head + (PAGE_SIZE * p));

		memset(tfree, 0, PAGE_SIZE);

		if (p)
			tfree->prev = pfree;

		if (p + 1 < n_ctrl_pages)
			tfree->next = nfree;

		for (n = 0; n < MAX_FREE_CHUNKS_PER_PAGE; n++) {
			safe_chunk_hdr_t *fhdr = (safe_chunk_hdr_t *)freeptr;

			fhdr->size = chunk_size;
			fhdr->flags = 0;

			tfree->free_chunks[n] = freeptr;
			freeptr += chunk_size;
			entries++;

			if (entries == total_chunks)
				break;

		}

	}

	*next_ptr = (safe_free_chunk_list_t *)freeptr;
	return 0;
}

void
_prepare_free_chunks(void) {
	void *all_init_chunks;
	size_t pages_required, leftover_pages, i;
	size_t ctrl_page_ct[N_CHUNK_BUCKETS];

	// Total page requirement is # raw memory pages + # chunk header pages
	pages_required = PAGE_PREALLOC_SIZE;
	// # pages per bucket is # total raw pages per bucket * (PAGE_SIZE / bucket_size),
	// as well as an extra safe_free_chunk_list_t *structure per page.

	leftover_pages = PAGE_PREALLOC_SIZE - ((PAGE_PREALLOC_SIZE / CHUNK_BUCKET_1_RATIO) + (PAGE_PREALLOC_SIZE / CHUNK_BUCKET_2_RATIO) +
		(PAGE_PREALLOC_SIZE / CHUNK_BUCKET_3_RATIO) + (PAGE_PREALLOC_SIZE / CHUNK_BUCKET_4_RATIO) +
		(PAGE_PREALLOC_SIZE / CHUNK_BUCKET_5_RATIO) + (PAGE_PREALLOC_SIZE / CHUNK_BUCKET_6_RATIO) +
		(PAGE_PREALLOC_SIZE / CHUNK_BUCKET_7_RATIO) + (PAGE_PREALLOC_SIZE / CHUNK_BUCKET_8_RATIO));

	ctrl_page_ct[0] = CTRL_PAGES_PER_BUCKET(CHUNK_BUCKET_1_RATIO, 16);
	ctrl_page_ct[1] = CTRL_PAGES_PER_BUCKET(CHUNK_BUCKET_2_RATIO, 32);
	ctrl_page_ct[2] = CTRL_PAGES_PER_BUCKET(CHUNK_BUCKET_3_RATIO, 64);
	ctrl_page_ct[3] = CTRL_PAGES_PER_BUCKET(CHUNK_BUCKET_4_RATIO, 128);
	ctrl_page_ct[4] = CTRL_PAGES_PER_BUCKET(CHUNK_BUCKET_5_RATIO, 256);
	ctrl_page_ct[5] = CTRL_PAGES_PER_BUCKET(CHUNK_BUCKET_6_RATIO, 512);
	ctrl_page_ct[6] = CTRL_PAGES_PER_BUCKET(CHUNK_BUCKET_7_RATIO, 1024);
	ctrl_page_ct[7] = CTRL_PAGES_PER_BUCKET(CHUNK_BUCKET_8_RATIO, 2048);
	ctrl_page_ct[8] = CEIL(leftover_pages, MAX_FREE_CHUNKS_PER_PAGE);

	for (i = 0; i < N_CHUNK_BUCKETS; i++)
		pages_required += ctrl_page_ct[i];

	safe_free_chunk_list_t *nextp = NULL;
	all_init_chunks = _allocate_pages(pages_required);

	free_chunk_buckets[0] = all_init_chunks;
	_carve_chunks(all_init_chunks, 16,   TOTAL_CHUNKS(CHUNK_BUCKET_1_RATIO, 16), &nextp);

	free_chunk_buckets[1] = nextp;
	_carve_chunks(nextp, 32,   TOTAL_CHUNKS(CHUNK_BUCKET_2_RATIO, 32), &nextp);

	free_chunk_buckets[2] = nextp;
	_carve_chunks(nextp, 64,   TOTAL_CHUNKS(CHUNK_BUCKET_3_RATIO, 64), &nextp);

	free_chunk_buckets[3] = nextp;
	_carve_chunks(nextp, 128,  TOTAL_CHUNKS(CHUNK_BUCKET_4_RATIO, 128), &nextp);

	free_chunk_buckets[4] = nextp;
	_carve_chunks(nextp, 256,  TOTAL_CHUNKS(CHUNK_BUCKET_5_RATIO, 256), &nextp);

	free_chunk_buckets[5] = nextp;
	_carve_chunks(nextp, 512,  TOTAL_CHUNKS(CHUNK_BUCKET_6_RATIO, 512), &nextp);

	free_chunk_buckets[6] = nextp;
	_carve_chunks(nextp, 1024, TOTAL_CHUNKS(CHUNK_BUCKET_7_RATIO, 1024), &nextp);

	free_chunk_buckets[7] = nextp;
	_carve_chunks(nextp, 2048, TOTAL_CHUNKS(CHUNK_BUCKET_8_RATIO, 2048), &nextp);

	free_chunk_buckets[8] = nextp;
	_carve_chunks(nextp, 4096, leftover_pages, &nextp);

	return;
}

void
_initialize_buckets(void) {
	size_t i;

	if (_bucket_init)
		return;

	for (i = 0; i < sizeof(bucket_locks)/sizeof(bucket_locks[0]); i++) {
		if (pthread_mutex_init(&bucket_locks[i], NULL))
			perror("pthread_mutex_init");
	}

	_prepare_free_chunks();
	_bucket_init = 1;
//	_dump_all_buckets();
	return;
}

inline void *
safe_malloc(size_t size) {
	safe_free_chunk_list_t *flist;
	safe_chunk_hdr_t *chdr;
	void *result = NULL;
	size_t bucket_idx;
	int flags = 0;

	_initialize_buckets();

	bucket_idx = _get_bucket_by_reqsize(size);

	if (bucket_idx < N_CHUNK_BUCKETS) {
		pthread_mutex_lock(&bucket_locks[bucket_idx]);
		flist = free_chunk_buckets[bucket_idx];
		result = _get_bucket_free_chunk(flist);
		pthread_mutex_unlock(&bucket_locks[bucket_idx]);
	}

	if (!result) {
		size_t real_size = size;

		real_size += sizeof(safe_chunk_hdr_t);

		if (real_size < 4096)
			real_size = 4096;
		else
			real_size = (real_size + PAGE_SIZE) & ~(PAGE_SIZE - 1);

		if ((result = mmap(NULL, real_size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
			return NULL;

		flags = CHUNK_FLAG_DIRECT_MAP;
	}

	chdr = (safe_chunk_hdr_t *)result;
	chdr->size = size;
	chdr->flags = flags;
	return (++chdr);
}

inline void
safe_free(void *ptr) {
	safe_free_chunk_list_t *flist;
	safe_chunk_hdr_t *chdr = (safe_chunk_hdr_t *)ptr;
	size_t bucket_idx;

	chdr--;

	_initialize_buckets();

	if (!ptr)
		return;

	if (chdr->flags & CHUNK_FLAG_DIRECT_MAP) {
		munmap(chdr, chdr->size);
		return;
	}

	bucket_idx = _get_bucket_by_reqsize(chdr->size);
	pthread_mutex_lock(&bucket_locks[bucket_idx]);
	flist = free_chunk_buckets[bucket_idx];

	if (_add_bucket_free_chunk(flist, chdr) != 0) {
		PRINT_ERROR("%s", "Error: safe allocator could not dispose of free chunk\n");
	}

	pthread_mutex_unlock(&bucket_locks[bucket_idx]);
	return;
}

inline void *
safe_realloc(void *ptr, size_t size) {
	safe_chunk_hdr_t *chdr = (safe_chunk_hdr_t *)ptr;
	void *result;

	chdr--;

	_initialize_buckets();

	// realloc in place if the original chunk is big enough
	// XXX: this is a naive implementation and could result in bloat since no memory actually freed
	// XXX: Also, the new size might be bigger, but still might be accommodated by current chunk.
	if (size <= chdr->size)
		return ptr;

	result = safe_malloc(size);

	if (!ptr)
		return result;

	memcpy(result, ptr, chdr->size);
	safe_free(ptr);
	return result;
}

inline char *
safe_strdup(const char *s) {
	char *result;
	size_t len;

	len = strlen(s) + 1;

	if (!(result = safe_malloc(len)))
		return NULL;

	memcpy(result, s, len);
	result[len] = 0;
	return result;
}



#ifdef USE_LIBUNWIND
void
backtrace_unwind(ucontext_t *start_context)
{
	unw_cursor_t cursor;
	unw_context_t context;
	unw_word_t last_ip = 0, last_sp = 0;
	size_t n = 1;
	pid_t this_thread;

	this_thread = syscall(SYS_gettid);

	if (start_context)
		unw_init_local(&cursor, start_context);
	else {
		unw_getcontext(&context);
		unw_init_local(&cursor, &context);

		if (!unw_step(&cursor)) {
			PRINT_ERROR_SAFE("%s", "Error starting unwound backtrace.\n");
			return;
		}

	}

	while (1) {
		char symname[128];
		unw_word_t ip, sp, off;

		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		unw_get_reg(&cursor, UNW_REG_SP, &sp);

		if (last_ip && last_sp && ip == last_ip && sp == last_sp) {
			PRINT_ERROR_SAFE("%s", "Backtrace seems to be caught in a loop; breaking.\n");
			break;
		}

		last_ip = ip, last_sp = sp;

		memset(symname, 0, sizeof(symname));

		if (unw_get_proc_name(&cursor, symname, sizeof(symname), &off))
			symname[0] = 0;

		if (off)
			PRINT_ERROR_SAFE("BACKTRACE[UW] (%d) / %zu %p <%s+0x%lx>\n", this_thread, n++,
			        (void *)ip, symname, off);
		else
			PRINT_ERROR_SAFE("BACKTRACE[UW] (%d) / %zu %p <%s>\n", this_thread, n++,
			        (void *)ip, symname);

		if (!unw_step(&cursor))
			break;

	}

	return;
}
#endif

void
_print_backtrace(void) {
#ifdef USE_LIBUNWIND
	backtrace_unwind(NULL);
#else
	void *btbuf[16];
	int nbt;

	nbt = backtrace(btbuf, 16);
	PRINT_ERROR_SAFE("Backtrace produced: %d addresses\n", nbt);

	backtrace_symbols_fd(btbuf, nbt, 2);
#endif
	return;
}


typedef struct demangle_buffer {
	char *buffer;
	size_t bufsize;
} demangle_buffer_t;

static void
_safe_demangle_cb(const char *buf, size_t bsize, void *opaque)
{
	demangle_buffer_t *dmbuf = opaque;
	size_t left, dlen, maxb;

	if (!dmbuf)
		return;

	dlen = strlen(dmbuf->buffer);
	left = dmbuf->bufsize - (dlen + 1);
	maxb = (left < bsize) ? left : bsize;
	strncpy(&dmbuf->buffer[dlen], buf, maxb);

	return;
}

int
_safe_demangle(const char *symname, char *buf, size_t bufsize) {
	demangle_buffer_t dmbuf;
	int ret;

	memset(&dmbuf, 0, sizeof(dmbuf));
	dmbuf.buffer = buf;
	dmbuf.bufsize = bufsize;
	ret = cplus_demangle_v3_callback(symname, 0, _safe_demangle_cb, &dmbuf);
	return ret;
}
