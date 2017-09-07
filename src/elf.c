#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

#include "config.h"
#include "elfh.h"


typedef struct link_symbols {
	struct link_map *l;
	symbol_mapping_t *map;
	size_t msize;
} link_symbols_t;

typedef struct address_mapping {
	unsigned char *addr;
	size_t size;
	char *name;
} addr_mapping_t;


link_symbols_t symbol_store[128];
addr_mapping_t *addr_mappings = NULL;
size_t addr_mapping_used = 0, addr_mapping_size = 0;

pthread_rwlock_t mapping_lock = PTHREAD_RWLOCK_INITIALIZER;


void
dump_address_mappings(void) {
	size_t i;

	pthread_rwlock_rdlock(&mapping_lock);
	fprintf(stderr, "A total of %zu mappings exist out of %zu allocated.\n", addr_mapping_used, addr_mapping_size);

	for (i = 0; i < addr_mapping_used; i++) {
		fprintf(stderr, "%zu: %p / %zu bytes: %s\n", i+1, addr_mappings[i].addr, addr_mappings[i].size,
			addr_mappings[i].name);
	}

	pthread_rwlock_unlock(&mapping_lock);
	return;
}

size_t
bsearch_address_mapping_unlocked(void *symaddr, size_t size, int *needs_insert) {
	unsigned char *caddr = (unsigned char *)symaddr;
	size_t i = 0, start_range, end_range;
	int keep_searching  = 1;

	start_range = 0;
	end_range = addr_mapping_used - 1;

	if (!addr_mapping_used) {
		*needs_insert = 1;
		return 0;
	}

	while (keep_searching) {
		i = start_range + ((end_range - start_range) / 2);

		if (start_range == end_range)
			keep_searching = 0;

		if (caddr < addr_mappings[i].addr) {
			end_range = i;

			if (end_range && (end_range > start_range))
				end_range--;

			continue;
		}

		if ((caddr >= addr_mappings[i].addr) && (caddr+size <= addr_mappings[i].addr+addr_mappings[i].size)) {
			*needs_insert = 0;
			return i;
		}

		if (end_range == start_range)
			break;

		start_range = i+1;
	}

	*needs_insert = 1;

	if (caddr < addr_mappings[i].addr)
		return i;

	return i+1;
}

void
add_address_mapping(void *symaddr, size_t size, const char *name) {
	size_t ind;
	int insert;

	pthread_rwlock_wrlock(&mapping_lock);

	if (!addr_mapping_size) {
		addr_mapping_size = 128;
		addr_mappings = malloc(sizeof(*addr_mappings) * addr_mapping_size);
	} else if (addr_mapping_used == addr_mapping_size) {
		addr_mapping_size *= 2;
		addr_mappings = realloc(addr_mappings, sizeof(*addr_mappings) * addr_mapping_size);
	}

	ind = bsearch_address_mapping_unlocked(symaddr, size, &insert);

	if (insert) {
		if (ind != addr_mapping_used) {
			memmove(&addr_mappings[ind+1], &addr_mappings[ind], sizeof(addr_mappings[0]) * (addr_mapping_used-ind));
		}

		addr_mappings[ind].addr = symaddr;
		addr_mappings[ind].size = size;
		addr_mappings[ind].name = strdup(name);
		addr_mapping_used++;
	} else {
		// For now, only permit a perfect overwrite
		if ((addr_mappings[ind].addr == symaddr) && (addr_mappings[ind].size == size)) {
			free(addr_mappings[ind].name);
			addr_mappings[ind].name = strdup(name);
		}

	}

	pthread_rwlock_unlock(&mapping_lock);
	return;
}

void
remove_address_mapping(void *symaddr, size_t size, const char *hint) {
	unsigned char *caddr = (unsigned char *)symaddr;
	size_t ind;
	int insert;

	pthread_rwlock_wrlock(&mapping_lock);

	ind = bsearch_address_mapping_unlocked(symaddr, size, &insert);

	if (insert) {

		if (hint)
			PRINT_ERROR("Warning: failed to lookup address mapping requested (%s) for removal at %p:%zu\n", hint, symaddr, size);
		else
			PRINT_ERROR("Warning: failed to lookup address mapping requested for removal at %p:%zu\n", symaddr, size);

	} else {

		// Freeing the whole thing or part of it?
		// Free the whole thing if our size requests match, or if size==0 was specified
		if ((addr_mappings[ind].addr == caddr) && ((size == addr_mappings[ind].size) || !size)) {
			free(addr_mappings[ind].name);
			memmove(&addr_mappings[ind], &addr_mappings[ind+1], sizeof(addr_mappings[0]) * (addr_mapping_used-(ind+1)));
			addr_mapping_used--;
		} else {

			// For right now only support removal at the beginning or end
			if (caddr == addr_mappings[ind].addr) {
				addr_mappings[ind].addr += addr_mappings[ind].size - size;
				addr_mappings[ind].size -= size;
			} else if (caddr + size == addr_mappings[ind].addr + addr_mappings[ind].size) {
				addr_mappings[ind].addr = caddr;
				addr_mappings[ind].size = size;
			}

		}

	}

	pthread_rwlock_unlock(&mapping_lock);
	return;
}

const char *
get_address_mapping(void *symaddr, size_t *offset) {
	unsigned char *caddr = (unsigned char *)symaddr;
	const char *name = NULL;
	size_t ind;
	int insert;

	pthread_rwlock_rdlock(&mapping_lock);

	ind = bsearch_address_mapping_unlocked(symaddr, 0, &insert);

	if (!insert) {
		name = addr_mappings[ind].name;
		*offset = (size_t)(caddr - addr_mappings[ind].addr);
	}

	pthread_rwlock_unlock(&mapping_lock);
	return name;
}

void
store_link_map_symbols(struct link_map *l, symbol_mapping_t *m, size_t sz) {
	size_t i;

	for (i = 0; i < sizeof(symbol_store)/sizeof(symbol_store[0]); i++) {

		if (!symbol_store[i].l) {
			symbol_store[i].l = l;
			symbol_store[i].map = m;
			symbol_store[i].msize = sz;
			break;
		}

	}

	return;
}

void *
lookup_symbol(const char *name) {
	size_t i;

	for (i = 0; i < sizeof(symbol_store)/sizeof(symbol_store[0]); i++) {
		void *addr;

		if (!symbol_store[i].l)
			continue;

		if ((addr = get_sym_addr(symbol_store[i].map, symbol_store[i].msize, name)))
			return addr;
			
	}

	return NULL;
}

const char *
lookup_addr(void *addr) {
	size_t i;

	for (i = 0; i < sizeof(symbol_store)/sizeof(symbol_store[0]); i++) {
		const char *name;

		if (!symbol_store[i].l)
			continue;

		if ((name = get_addr_name(symbol_store[i].map, symbol_store[i].msize, addr)))
			return name;
			
	}

	return NULL;
}

int
get_all_symbols(struct link_map *lm, symbol_mapping_t **pmap, size_t *msize, int debug) {
	symbol_mapping_t *result, *rptr;
	Elf64_Dyn *dyn = (Elf64_Dyn *)lm->l_ld;
	Elf64_Sym *symtab = NULL;
	void *osym = NULL;
	char *strtab = NULL, *rstrtab;
	size_t strtab_size = 0, syment_size = 0, rsize = 0, nsyms = 0;

	if (debug)
		fprintf(stderr, "ELF debug: base addr = %p\n", (void *)lm->l_addr);

	while (dyn->d_tag != DT_NULL) {

		if (dyn->d_tag == DT_STRSZ)
			strtab_size = dyn->d_un.d_val;
		else if (dyn->d_tag == DT_SYMENT)
			syment_size = dyn->d_un.d_val;
		else if (dyn->d_tag == DT_STRTAB)
			strtab = (void *)dyn->d_un.d_ptr;
		else if (dyn->d_tag == DT_SYMTAB)
			osym = symtab = (Elf64_Sym *)dyn->d_un.d_ptr;

		if (debug) {
			if (dyn->d_tag == DT_RELENT)
				fprintf(stderr, "ELF debug: relent = %lu\n", dyn->d_un.d_val);
			else if (dyn->d_tag == DT_RELSZ)
				fprintf(stderr, "ELF debug: relsz = %lu\n", dyn->d_un.d_val);
			else if (dyn->d_tag == DT_PLTRELSZ)
				fprintf(stderr, "ELF debug: plt relsz = %lu\n", dyn->d_un.d_val);
			else if (dyn->d_tag == DT_PLTGOT)
				fprintf(stderr, "ELF debug: pltgot = %p\n", (void *)dyn->d_un.d_ptr);
			else if (dyn->d_tag == DT_RELA)
				fprintf(stderr, "ELF debug: rela = %p\n", (void *)dyn->d_un.d_ptr);
			else if (dyn->d_tag == DT_REL)
				fprintf(stderr, "ELF debug: rel = %p\n", (void *)dyn->d_un.d_ptr);
			else if (dyn->d_tag == DT_TEXTREL)
				fprintf(stderr, "ELF debug: textrel = %p\n", (void *)dyn->d_un.d_ptr);
			else if (dyn->d_tag == DT_JMPREL)
				fprintf(stderr, "ELF debug: jmprel = %p\n", (void *)dyn->d_un.d_ptr);
		}

		dyn++;
	}

	if (!strtab_size || !syment_size || !strtab || !symtab)
		return 0;

	while (1) {

		if (symtab->st_name >= strtab_size)
			break;

		if (symtab->st_value == 0) {
			symtab++;
			continue;
		}

		if ((ELF64_ST_TYPE(symtab->st_info) == STT_OBJECT) || (ELF64_ST_TYPE(symtab->st_info) == STT_TLS))
			add_address_mapping((void *)symtab->st_value+lm->l_addr, symtab->st_size, strtab+symtab->st_name);

		if (ELF64_ST_TYPE(symtab->st_info) != STT_FUNC) {
			symtab++;
			continue;
		}

		symtab++, nsyms++;
	}

	rsize = strtab_size + (nsyms * sizeof(symbol_mapping_t));
	
	if (!(result = malloc(rsize))) {
		perror("malloc");
		return 0;
	}

	memset(result, 0, rsize);
	rstrtab = (char *)result + rsize - strtab_size;
	memcpy(rstrtab, strtab, strtab_size);

	symtab = (Elf64_Sym *)osym;
	rptr = result;

	while (1) {

		if (symtab->st_name >= strtab_size)
			break;

		if (symtab->st_value == 0) {
			symtab++;
			continue;
		}

		if (ELF64_ST_TYPE(symtab->st_info) != STT_FUNC) {
			symtab++;
			continue;
		}

		if (ELF64_ST_TYPE(symtab->st_info) != STT_FUNC) {
//			fprintf(stderr, "XXX: %s / %d\n", rstrtab+symtab->st_name, ELF64_ST_TYPE(symtab->st_info));
		}

		rptr->addr = (unsigned long)lm->l_addr + symtab->st_value;
		rptr->name = rstrtab + symtab->st_name;
		symtab++, rptr++;
	}


	*pmap = result;
	*msize = nsyms;

	return 1;
}

void *
get_sym_addr(symbol_mapping_t *map, size_t sz, const char *name) {
	size_t i;

	for (i = 0; i < sz; i++) {

		if (!strcmp(map[i].name, name))
			return (void *)map[i].addr;

	}

	return NULL;
}

const char *
get_addr_name(symbol_mapping_t *map, size_t sz, void *addr) {
	size_t i;

	for (i = 0; i < sz; i++) {

		if (((void *)map[i].addr == addr))
			return (void *)map[i].name;

	}

	return NULL;
}
