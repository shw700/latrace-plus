#include <stdio.h>
#include <string.h>

#include "elfh.h"


typedef struct link_symbols {
	struct link_map *l;
	symbol_mapping_t *map;
	size_t msize;
} link_symbols_t;


link_symbols_t symbol_store[128];


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
get_all_symbols(struct link_map *lm, symbol_mapping_t **pmap, size_t *msize) {
	symbol_mapping_t *result, *rptr;
	Elf64_Dyn *dyn = (Elf64_Dyn *)lm->l_ld;
	Elf64_Sym *symtab = NULL;
	void *osym = NULL;
	char *strtab = NULL, *rstrtab;
	size_t strtab_size = 0, syment_size = 0, rsize = 0, nsyms = 0;

	while (dyn->d_tag != DT_NULL) {

		if (dyn->d_tag == DT_STRSZ)
			strtab_size = dyn->d_un.d_val;
		else if (dyn->d_tag == DT_SYMENT)
			syment_size = dyn->d_un.d_val;
		else if (dyn->d_tag == DT_STRTAB)
			strtab = (void *)dyn->d_un.d_ptr;
		else if (dyn->d_tag == DT_SYMTAB)
			osym = symtab = (Elf64_Sym *)dyn->d_un.d_ptr;

		else if (dyn->d_tag == DT_RELENT)
			printf("relent = %lu\n", dyn->d_un.d_val);
		else if (dyn->d_tag == DT_RELSZ)
			printf("relsz = %lu\n", dyn->d_un.d_val);

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

		rptr->addr = symtab->st_value;
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
