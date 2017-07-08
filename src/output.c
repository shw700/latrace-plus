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

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "config.h"

static char spaces[] = "                                                                                                                                                                           ";

static int print_details(struct lt_config_shared *cfg, char *argdbuf)
{
	fprintf(cfg->fout, "%s\n", argdbuf);
	return 0;
}

#define PRINT_TID(tid) \
do { \
	fprintf(cfg->fout, "%5d   ", tid); \
} while(0)

#define PRINT_TIME(tv) \
do { \
	struct tm t; \
\
	gettimeofday(tv, NULL); \
	localtime_r(&tv->tv_sec, &t); \
	fprintf(cfg->fout, "[%02d/%02d/%4d %02d:%02d:%02d.%06u]   ", \
		t.tm_mon, \
		t.tm_mday, \
		t.tm_year + 1900, \
		t.tm_hour, \
		t.tm_min, \
		t.tm_sec, \
		(unsigned int) tv->tv_usec); \
} while(0)

/* libiberty external */
extern char* cplus_demangle(const char *mangled, int options);

#ifdef CONFIG_LIBERTY
#define DEMANGLE(sym, d) \
do { \
	char *dem; \
	dem = cplus_demangle(sym, 0); \
	if (dem) { \
		sym = dem; \
		d = 1; \
	} \
} while(0)
#else
#define DEMANGLE(sym, d)
#endif

char *color_table[6] = { RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN };

int lt_out_entry(struct lt_config_shared *cfg,
			struct timeval *tv, pid_t tid,
			int indent_depth,
			const char *symname, char *lib_to,
			char *argbuf, char *argdbuf)
{
	const char *cur_color = NULL;
	int demangled = 0;

	if (cfg->timestamp && tv)
		PRINT_TIME(tv);

	/* Print thread ID */
	if (!cfg->hide_tid)
		PRINT_TID(tid);

	/* Print indentation. */
	if (indent_depth && cfg->indent_sym) {

		if (cfg->fmt_colors)
			cur_color = color_table[indent_depth % sizeof(color_table)];

		fprintf(cfg->fout, "%.*s", indent_depth * cfg->indent_size, spaces);
	}

	/* Demangle the symbol if needed */
	if (cfg->demangle)
		DEMANGLE(symname, demangled);

	if (lt_sh(cfg, lib_short)) {
		char *rptr = strrchr(lib_to, '/');

		if (rptr)
			lib_to = ++rptr;
	}

	/* Print the symbol and arguments. */
	if (cur_color) {
		if (*argbuf)
			fprintf(cfg->fout, "%s%s%s%s(%s%s%s) [%s] {\n",
				BOLD, cur_color, symname, RESET, cur_color, argbuf, RESET, lib_to);
		else
			fprintf(cfg->fout, "%s%s%s [%s] %c\n", 
						cur_color, symname, RESET, lib_to,
						cfg->braces ? '{' : ' ');
	} else {
		if (*argbuf)
			fprintf(cfg->fout, "%s(%s) [%s] {\n", symname, argbuf, lib_to);
		else
			fprintf(cfg->fout, "%s [%s] %c\n", 
						symname, lib_to,
						cfg->braces ? '{' : ' ');
	}

	if (demangled)
		free((char*) symname);

	/* Print arguments' details. */
	if (cfg->args_detailed && *argdbuf)
		print_details(cfg, argdbuf);

	fflush(NULL);
	return 0;
}

int lt_out_exit(struct lt_config_shared *cfg,
			struct timeval *tv, pid_t tid,
			int indent_depth,
			const char *symname, char *lib_to,
			char *argbuf, char *argdbuf)
{
	const char *cur_color = NULL;
	int demangled = 0;

	if (!*argbuf && (!cfg->braces))
		return 0;

	if (cfg->timestamp && tv)
		PRINT_TIME(tv);

	/* Print thread ID */
	if (!cfg->hide_tid)
		PRINT_TID(tid);

	/* Print indentation. */
	if (indent_depth && cfg->indent_sym) {

		if (cfg->fmt_colors)
			cur_color = color_table[indent_depth % sizeof(color_table)];

		fprintf(cfg->fout, "%.*s", indent_depth * cfg->indent_size, spaces);
	}

	/* We got here, because we have '-B' option enabled. */
	if (!*argbuf && (cfg->braces)) {
		fprintf(cfg->fout, "}\n");
		return 0;
	}

	/* Demangle the symbol if needed */
	if (cfg->demangle)
		DEMANGLE(symname, demangled);

	/* Print the symbol and arguments. */
	if (cur_color)
		fprintf(cfg->fout, "} %s%s%s%s%s\n", BOLD, cur_color, symname, RESET, argbuf);
	else
		fprintf(cfg->fout, "} %s%s\n", symname, argbuf);

	if (demangled)
		free((char*) symname);

	/* Print arguments' details. */
	if (cfg->args_detailed && *argdbuf)
		print_details(cfg, argdbuf);

	fflush(NULL);
	return 0;
}
