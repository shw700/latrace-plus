#include <link.h>
#include <elf.h>


typedef struct symbol_mapping {
	unsigned long addr;
	char *name;
} symbol_mapping_t;


void store_link_map_symbols(struct link_map *l, symbol_mapping_t *m, size_t sz);
int get_all_symbols(struct link_map *lh, symbol_mapping_t **pmap, size_t *msize, int debug);
void *lookup_symbol(const char *name);
const char *lookup_addr(void *addr);
void *get_sym_addr(symbol_mapping_t *map, size_t sz, const char *name);
const char *get_addr_name(symbol_mapping_t *map, size_t sz, void *addr);

const char *get_address_mapping(void *symaddr, size_t *offset);
void add_address_mapping(void *symaddr, size_t size, const char *name);
void remove_address_mapping(void *symaddr, size_t size, const char *hint);

char *resolve_sym(void *addr, int exact, char *buf, size_t buflen, const char **filename);
