/*
  Copyright (C) 2008, 2009, 2010 Jiri Olsa <olsajiri@gmail.com>

  This file is part of the latrace.

  The latrace is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The latrace is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the latrace (file COPYING).  If not, see 
  <http://www.gnu.org/licenses/>.
*/


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

#include <libelf.h>
#include <gelf.h>
#include <glob.h>

#include "config.h"

struct lt_config_audit cfg;
struct hsearch_data args_struct_xfm_tab;
struct hsearch_data args_func_xfm_tab;
struct hsearch_data args_func_intercept_tab;


static int init_ctl_config(char *file)
{
	void *sh;
	int len;
	int page = sysconf(_SC_PAGE_SIZE);
	int fd;

	if (-1 == (fd = open(file, O_RDWR))) {
		PRINT_ERROR("open failed on config file %s: %s\n", file, strerror(errno));
		return -1;
	}

	/* align the shared config length */
	len = sizeof(struct lt_config_shared);
	len = (len + page) & ~(page - 1);

	sh = mmap(NULL, len,
		PROT_READ | PROT_WRITE,
		MAP_SHARED, fd, 0);

	if ((void *) -1 == sh) {
		PRINT_VERBOSE(&cfg, 1,
			"mmap failed: %s\n", strerror(errno));
		return -1;
	}

	/* switching to the mmaped shared config */
	cfg.sh = sh;

	/* PRINT_VERBOSE magic */
	cfg.sh->sh = sh;
	return 0;
}

static int read_config(char *dir)
{
	int fd;
	off_t len;
	char file[LT_MAXFILE];

	memset(&cfg, 0, sizeof(cfg));

	cfg.dir = dir;
	sprintf(file, "%s/config", dir);

	if (-1 == (fd = open(file, O_RDONLY))) {
		PRINT_ERROR("open failed on config file %s: %s\n", file, strerror(errno));
		return -1;
	}

	if (-1 == read(fd, &cfg.sh_storage, sizeof(cfg.sh_storage))) {
		perror("read failed");
		return -1;
	}

	if (-1 == (len = lseek(fd, 0, SEEK_END))) {
		perror("lseek failed");
		return -1;
	}

	if (len != sizeof(cfg.sh_storage)) {
		printf("config file size differs (expected %zu bytes)\n", sizeof(cfg.sh_storage));
		return -1;
	}

	if (LT_CONFIG_MAGIC != cfg.sh_storage.magic) {
		PRINT_ERROR("%s", "config file magic check failed\n");
		return -1;
	}

	cfg.sh = cfg.sh_storage.sh = &cfg.sh_storage;

	/*
	 * If we are not controlled, we can close the file,
	 * since we read everything we needed.
	 */
	close(fd);

	if (lt_sh(&cfg, ctl_config) && init_ctl_config(file))
		printf("ctl config failed, carring on with standard\n");

	return 0;
}

static int get_names(struct lt_config_audit *cfg, char *names, char **ptr)
{
	char* s;
	int cnt = 0;

	PRINT_VERBOSE(cfg, 1, "names: [%s] max: %d\n",
			names, LT_NAMES_MAX);

	s = strchr(names, LT_NAMES_SEP);
	while(NULL != (s = strchr(names, LT_NAMES_SEP)) && (cnt < LT_NAMES_MAX)) {
		*s = 0x0;
		PRINT_VERBOSE(cfg, 1, "got: %s", names);
		ptr[cnt++] = names;
		names = ++s;
	}

	if (cnt) {
		ptr[cnt++] = names;
		PRINT_VERBOSE(cfg, 1, "got: %s\n", names);
	}

	if (!cnt && *names) {
		ptr[0] = names;
		cnt = 1;
		PRINT_VERBOSE(cfg, 1, "got: %s\n", names);
	}

	ptr[cnt] = NULL;

	if (!cnt)
		return -1;

	PRINT_VERBOSE(cfg, 1, "got %d entries\n", cnt);
	return cnt;
}

static size_t get_symtab_size(const char *filename, size_t *strtab_size)
{
	Elf *elf;
	int fd;
	size_t sym_count;

	if ((fd = open(filename, O_RDONLY)) < 0) {
		perror("open");
		return 0;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		PRINT_ERROR("elf_version: %s\n", elf_errmsg(elf_errno()));
		close(fd);
		return 0;
	}

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == 0) {
		PRINT_ERROR("Error reading ELF header of shared object: %s\n", filename);
		PRINT_ERROR("elf_begin: %s\n", elf_errmsg(elf_errno()));
		close(fd);
		return 0;
	}

	Elf_Scn *section = elf_getscn(elf, 0);

	*strtab_size = 0;

	while (section) {
		GElf_Shdr shdr;
		gelf_getshdr(section, &shdr);

		if (shdr.sh_type == SHT_STRTAB)
			*strtab_size = shdr.sh_size;
		else if (shdr.sh_type == SHT_SYMTAB)
			sym_count = shdr.sh_size / shdr.sh_entsize;

		section = elf_nextscn(elf, section);
	}

	close(fd);
	return sym_count;
}


static int setup_user_data_handlers(void)
{

	if (!hcreate_r(LT_ARGS_DEF_ENUM_NUM, &args_struct_xfm_tab)) {
		perror("failed to create hash table:");
		return -1;
	}

	if (!hcreate_r(LT_ARGS_DEF_ENUM_NUM, &args_func_xfm_tab)) {
		perror("failed to create hash table:");
		return -1;
	}

	if (!hcreate_r(LT_ARGS_DEF_ENUM_NUM, &args_func_intercept_tab)) {
		perror("failed to create hash table:");
		return -1;
	}

	return 0;
}


int glob_err(const char *epath, int eerrno) {
	PRINT_ERROR("Encountered globbing error: %s\n", strerror(eerrno));
	return 0;
}

#define STRUCT_TRANSFORM_PREFIX	"latrace_struct_to_str_"
#define FUNC_TRANSFORM_PREFIX	"latrace_func_to_str_"
#define FUNC_INTERCEPT_PREFIX	"latrace_func_intercept_"
int init_custom_handlers(struct lt_config_audit *cfg)
{
	static char globdir[sizeof(LT_CONF_TRANSFORMERS_DIR)+8];
	glob_t rglob;
	size_t i;
	int ret;

	if (setup_user_data_handlers() < 0) {
		PRINT_ERROR("%s", "Unexpected error setting up function transformers table");
		return -1;
	}

	#ifdef TRANSFORMER_CRASH_PROTECTION
	if (setup_crash_handlers() < 0) {
		PRINT_ERROR("%s", "Error setting up transformer crash protection\n");
		return -1;
	}
	#endif

	if (!globdir[0])
		snprintf(globdir, sizeof(globdir), "%s/*.so", LT_CONF_TRANSFORMERS_DIR);

	ret = glob(globdir, GLOB_ERR, glob_err, &rglob);

	if (ret != 0 && ret != GLOB_NOMATCH) {
		PRINT_ERROR("Unable to read transformers libraries directory: %s\n", strerror(errno));
		return -1;
	}

	for (i = 0; i < rglob.gl_pathc; i++) {
		struct link_map *lmap = NULL;
		Elf64_Dyn *dyn;
		Elf64_Sym *symtab = NULL;
		void *handle;
		char *lpath = rglob.gl_pathv[i], *strtab = NULL, *symstr;
		size_t symtab_size, strtab_size, sym_count = 0;

		PRINT_VERBOSE(cfg, 1, "Checking user-supplied transformer library: %s\n", lpath);

		if (!(handle = dlopen(lpath, RTLD_NOW|RTLD_LOCAL))) {
			PRINT_ERROR("Error loading shared library %s: %s\n", lpath, dlerror());
			continue;
		}

		if (dlinfo(handle, RTLD_DI_LINKMAP, &lmap) != 0) {
			PRINT_ERROR("Error retrieving shared library info for %s: %s\n", lpath, dlerror());
			dlclose(handle);
			continue;
		}

		dyn = (Elf64_Dyn *) lmap->l_ld;

		while (dyn->d_tag != DT_NULL) {

			if (dyn->d_tag == DT_SYMTAB) {
				symtab = (Elf64_Sym *)dyn->d_un.d_ptr;
				PRINT_VERBOSE(cfg, 2, "Symtab of %s found at %p\n", lpath, (void *)dyn->d_un.d_ptr);
			} else if (dyn->d_tag == DT_SYMENT) {
				PRINT_VERBOSE(cfg, 3, "Determined syment size of transformer lib %s: %lu\n", lpath, dyn->d_un.d_val);

				if (dyn->d_un.d_val != sizeof(Elf64_Sym)) {
					PRINT_ERROR("Unexpected ELF object symbol table entry size was %lu bytes vs %zu\n", dyn->d_un.d_val, sizeof(Elf64_Sym));
					dlclose(handle);
					continue;
				}

			}
			else if (dyn->d_tag == DT_STRTAB) {
				strtab = (char *)dyn->d_un.d_ptr;
				PRINT_VERBOSE(cfg, 2, "String table of %s found at %p\n", lpath, (void *)dyn->d_un.d_ptr);
			}

			dyn++;
		}

		if (!symtab) {
			PRINT_ERROR("Error: could not determine address of symbol table for transformer library %s", lpath);
			dlclose(handle);
			continue;
		} else if (!strtab) {
			PRINT_ERROR("Error: could not determine address of string table for transformer library %s", lpath);
			dlclose(handle);
			continue;
		}

		symtab_size = get_symtab_size(lpath, &strtab_size);
		PRINT_VERBOSE(cfg, 2, "In-memory symtab size of %s: %zu entries\n", lpath, symtab_size);

		while (sym_count < symtab_size) {
			if (symtab->st_name >= strtab_size)
				break;

			if (ELF64_ST_TYPE(symtab->st_info) == STT_FUNC) {
				symstr = strtab + symtab->st_name;
				PRINT_VERBOSE(cfg, 3, "Found exported function in %s: %s @ %p\n", lpath, symstr, (void *)symtab->st_value);

				if (!strncmp(symstr, STRUCT_TRANSFORM_PREFIX, strlen(STRUCT_TRANSFORM_PREFIX))) {
					void *sym_addr;
					char *funcname = symstr + strlen(STRUCT_TRANSFORM_PREFIX);
					ENTRY e, *ep;

					PRINT_VERBOSE(cfg, 1, "Adding user struct transformer function for type: %s\n", funcname);
					PRINT_ERROR("Adding user struct transformer function for type: %s\n", funcname);

					if (!(sym_addr = dlsym(handle, symstr))) {
						PRINT_ERROR("dlsym: %s\n", dlerror());
						symtab++, sym_count++;
						continue;
					}

					e.key = strdup(funcname);
					e.data = sym_addr;

					if (!hsearch_r(e, ENTER, &ep, &args_struct_xfm_tab)) {
						perror("hsearch_r failed");
						symtab++, sym_count++;
						continue;
					}

				} else if (!strncmp(symstr, FUNC_TRANSFORM_PREFIX, strlen(FUNC_TRANSFORM_PREFIX))) {
					void *sym_addr;
					char *funcname = symstr + strlen(FUNC_TRANSFORM_PREFIX);
					ENTRY e, *ep;

					PRINT_VERBOSE(cfg, 1, "Adding user transformer function for function: %s()\n", funcname);
					PRINT_ERROR("Adding user transformer function for function: %s()\n", funcname);

					if (!(sym_addr = dlsym(handle, symstr))) {
						PRINT_ERROR("dlsym: %s\n", dlerror());
						symtab++, sym_count++;
						continue;
					}

					e.key = strdup(funcname);
					e.data = sym_addr;

					if (!hsearch_r(e, ENTER, &ep, &args_func_xfm_tab)) {
						perror("hsearch_r failed");
						symtab++, sym_count++;
						continue;
					}

				} else if (!strncmp(symstr, FUNC_INTERCEPT_PREFIX, strlen(FUNC_INTERCEPT_PREFIX))) {
					void *sym_addr;
					char *funcname = symstr + strlen(FUNC_INTERCEPT_PREFIX);
					ENTRY e, *ep;

					PRINT_VERBOSE(cfg, 1, "Adding user intercept function for function: %s()\n", funcname);
					PRINT_ERROR("Adding user intercept function for function: %s()\n", funcname);

					if (!(sym_addr = dlsym(handle, symstr))) {
						PRINT_ERROR("dlsym: %s\n", dlerror());
						symtab++, sym_count++;
						continue;
					}

					e.key = strdup(funcname);
					e.data = sym_addr;

					if (!hsearch_r(e, ENTER, &ep, &args_func_intercept_tab)) {
						perror("hsearch_r failed");
						symtab++, sym_count++;
						continue;
					}

				}

			}

			symtab++, sym_count++;
		}

	}

	globfree(&rglob);
	return 0;
}

int audit_init(int argc, char **argv, char **env)
{

	if (!getenv("LT_DIR")) {
		PRINT_ERROR("%s", "Error: LT_DIR environment variable must be set!\n");
		return -1;
	} else if (-1 == read_config(getenv("LT_DIR")))
		return -1;

	if (init_custom_handlers(&cfg) < 0) {
	}

#ifdef CONFIG_ARCH_HAVE_ARGS
	/* -Aa */
	if (lt_sh(&cfg, args_enabled) && lt_args_init(cfg.sh))
		return -1;
#endif

	/* -t */
	if ((*lt_sh(&cfg, libs_to)) &&
	    (-1 == (cfg.libs_to_cnt = get_names(&cfg, lt_sh(&cfg, libs_to),
						cfg.libs_to)))) {
		PRINT_ERROR("%s", "latrace failed to parse libs to\n");
		return -1;
	}

	/* -f */
	if ((*lt_sh(&cfg, libs_from)) &&
	    (-1 == (cfg.libs_from_cnt = get_names(&cfg, lt_sh(&cfg, libs_from),
						  cfg.libs_from)))) {
		PRINT_ERROR("%s", "latrace failed to parse libs from\n");
		return -1;
	}

	/* -l */
	if ((*lt_sh(&cfg, libs_both)) &&
	    (-1 == (cfg.libs_both_cnt = get_names(&cfg, lt_sh(&cfg, libs_both),
						  cfg.libs_both)))) {
		PRINT_ERROR("%s", "latrace failed to parse libs from\n");
		return -1;
	}

	/* -s */
	if ((*lt_sh(&cfg, symbols)) &&
	    (-1 == (cfg.symbols_cnt = get_names(&cfg, lt_sh(&cfg, symbols),
						cfg.symbols)))) {
		PRINT_ERROR("%s", "latrace failed to parse symbols\n");
		return -1;
	}

	/* -n */
	if ((*lt_sh(&cfg, symbols_omit)) &&
	    (-1 == (cfg.symbols_omit_cnt = get_names(&cfg, lt_sh(&cfg, symbols_omit),
						     cfg.symbols_omit)))) {
		PRINT_ERROR("%s", "latrace failed to parse symbols to omit\n");
		return -1;
	}

	/* SYM_NOEXIT option */
	if ((*lt_sh(&cfg, symbols_noexit)) &&
	    (-1 == (cfg.symbols_noexit_cnt = get_names(&cfg, lt_sh(&cfg, symbols_noexit),
						       cfg.symbols_noexit)))) {
		PRINT_ERROR("%s", "latrace failed to parse noexit symbols\n");
		return -1;
	}

	/* -b */
	if ((*lt_sh(&cfg, flow_below)) &&
	    (-1 == (cfg.flow_below_cnt = get_names(&cfg, lt_sh(&cfg, flow_below),
						   cfg.flow_below)))) {
		PRINT_ERROR("%s", "latrace failed to parse symbols in flow-below option\n");
		return -1;
	}

	/* -L */
	if (*lt_sh(&cfg, libs_subst)) {

		char *ptr[LT_NAMES_MAX];
		int cnt;

		if (-1 == (cnt = get_names(&cfg, lt_sh(&cfg, libs_subst), ptr))) {
			PRINT_ERROR("%s", "latrace failed to parse input for subst option\n");
			return -1;
		}

		if (-1 == lt_objsearch_init(&cfg, ptr, cnt)) {
			PRINT_ERROR("%s", "latrace failed to nitialize subst option\n");
			return -1;
		}
	}

	/* -o FIXME put fout out of the shared structure */
	lt_sh(&cfg, fout) = stdout;
	if ((*lt_sh(&cfg, output)) &&
	    (NULL == (lt_sh(&cfg, fout) = fopen(lt_sh(&cfg, output), "w")))) {
		PRINT_ERROR("latrace failed to open output file %s\n", lt_sh(&cfg, output));
		return -1;
	}

	/* -E */
	if (lt_sh(&cfg, not_follow_exec))
		unsetenv("LD_AUDIT");

	/* -F */
	if (lt_sh(&cfg, not_follow_fork))
		lt_sh(&cfg, pid) = getpid();

	/* enable global symbols if needed */
	lt_sh(&cfg, global_symbols) = lt_sh(&cfg, args_enabled);
	PRINT_VERBOSE(&cfg, 1, "global_symbols %d\n", lt_sh(&cfg, global_symbols));

	cfg.init_ok = 1;
	return 0;
}

void finalize(void) __attribute__((destructor));

void
finalize(void)
{
	if ((!lt_sh(&cfg, pipe)) && (*lt_sh(&cfg, output)))
		fclose(lt_sh(&cfg, fout));
}
