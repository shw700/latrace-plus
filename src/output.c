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
#include <stdarg.h>
#include <pthread.h>

#include "config.h"


static char spaces[] = "                                                                                                                                                                           ";


typedef struct thread_buffer {
	pid_t tid;
	char *buf;
	struct thread_buffer *next;
	int last_nested;
} thread_buffer_t;

thread_buffer_t *thread_buffers = NULL;
pthread_mutex_t threadbuf_lock = PTHREAD_MUTEX_INITIALIZER;

#define PRINT_DETAILS(tobuf,buf) \
do { \
	if (tobuf) \
		outbuf = sprintf_cat(outbuf, 8192, "%s\n", buf); \
	else \
		print_details(cfg, buf); \
} while(0)

static int print_details(struct lt_config_shared *cfg, char *argdbuf)
{
	fprintf(cfg->fout, "%s\n", argdbuf);
	return 0;
}

#define PRINT_DATA(tobuf,fmt,...) \
do { \
	if (!tobuf) { \
		fprintf(cfg->fout, fmt, __VA_ARGS__); \
		fflush(NULL); \
	} \
	else { \
		outbuf = sprintf_cat(outbuf, 8192, fmt, __VA_ARGS__); \
	} \
} while(0)

#define FPRINT_TID(tid) \
do { \
	fprintf(cfg->fout, "%5d   ", tid); \
} while(0)
#define SPRINT_TID(tid) \
do { \
	outbuf = sprintf_cat(outbuf, 8192, "%5d   ", tid); \
} while(0)

#define FPRINT_TIME(tv) \
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
#define SPRINT_TIME(tv) \
do { \
	struct tm t; \
\
	gettimeofday(tv, NULL); \
	localtime_r(&tv->tv_sec, &t); \
	outbuf = sprintf_cat(outbuf, 8192, "[%02d/%02d/%4d %02d:%02d:%02d.%06u]   ", \
		t.tm_mon, \
		t.tm_mday, \
		t.tm_year + 1900, \
		t.tm_hour, \
		t.tm_min, \
		t.tm_sec, \
		(unsigned int) tv->tv_usec); \
} while(0)

char *color_table[6] = { RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN };


static char *
sprintf_cat(char *buf, size_t bufsize, char *fmt, ...)
{
	va_list ap;
	char tmpbuf[1024], *result;
	int csize, nsize = 0;

	va_start(ap, fmt);
	memset(tmpbuf, 0, sizeof(tmpbuf));
	csize = vsnprintf(tmpbuf, sizeof(tmpbuf), fmt, ap);
	va_end(ap);

	if (csize < 0)
		return NULL;

	if (!buf)
		XSTRDUP_ASSIGN(result, tmpbuf);
	else {
		nsize = strlen(buf) + csize + 1;
		XREALLOC_ASSIGN(result, buf, nsize);
		strncat(result, tmpbuf, csize);
	}

	return result;
}

static void
buffer_output_data(pid_t tid, const char *output, int nest_level, int do_prefix)
{
	thread_buffer_t *tb;
	char *outbuf;
	size_t nlen = 0;
	int was_empty = 0;
	int nested = 1;

	if (!output || !*output)
		return;

	pthread_mutex_lock(&threadbuf_lock);
	tb = thread_buffers;

	while (tb && (tb->tid != tid))
		tb = tb->next;

	if (tb && tb->buf)
		nlen += strlen(tb->buf);
	else
		was_empty = 1;

	if (do_prefix)
		nlen += 8;

	nlen += strlen(output) + 1;

	if (was_empty)
		XMALLOC_ASSIGN(outbuf, nlen);
	else
		XREALLOC_ASSIGN(outbuf, tb->buf, nlen);

	if (!outbuf) {
		PRINT_ERROR("%s", "Error: unable to allocate memory for output buffer");
		pthread_mutex_unlock(&threadbuf_lock);
		return;
	}

	if (was_empty)
		strcpy(outbuf, output);
	else if (nest_level > tb->last_nested)
		nested = 1;
	else if (tb->last_nested > nest_level)
		nested = -1;
	else
		nested = 0;

	if (do_prefix) {
		if (nested > 0)
			strcat(outbuf, " -> ");
		else if (nested < 0)
			strcat(outbuf, " | ");
		else if (!was_empty)
			strcat(outbuf, ", ");
	}

	if (!was_empty)
		strcat(outbuf, output);

	if (!tb) {

		XMALLOC_ASSIGN(tb, sizeof(*tb));
		if (!tb) {
			PRINT_ERROR("%s", "Error: unable to allocate memory for output buffer");
			pthread_mutex_unlock(&threadbuf_lock);
			return;
		}

		memset(tb, 0, sizeof(thread_buffer_t));
		tb->tid = tid;
		tb->next = thread_buffers;
		thread_buffers = tb;
	}

	tb->buf = outbuf;
	tb->last_nested = nest_level;
	pthread_mutex_unlock(&threadbuf_lock);
	return;
}

char *
pop_output_data(pid_t tid)
{
	thread_buffer_t *tb;
	char *result;

	pthread_mutex_lock(&threadbuf_lock);
	tb = thread_buffers;

	while (tb && (tb->tid != tid))
		tb = tb->next;

	if (!tb)
		result = NULL;
	else {
		result = tb->buf;
		tb->buf = NULL;
		tb->last_nested = 0;

/*		if (tb != thread_buffers) {
			tb->next = thread_buffers;
			thread_buffers = tb;
		} */

	}

	pthread_mutex_unlock(&threadbuf_lock);
	return result;
}

int lt_out_entry(struct lt_config_shared *cfg,
			struct timeval *tv, pid_t tid,
			int indent_depth, int collapsed,
			const char *symname, char *lib_to,
			char *argbuf, char *argdbuf,
			size_t *nsuppressed)
{
	const char *cur_color = NULL;
	const char *end_line = "{\n";
	int demangled = 0;
	char *outbuf = NULL;
	int buffered;

	buffered = (collapsed > 0);

	/* Would probably be helpful to pre-allocate buffer for data and not constantly resize it */
/*	if (buffered) {
		XMALLOC_ASSIGN(outbuf, 8192);
		memset(outbuf, 0, sizeof(outbuf));
	} */

	if (!symname && argbuf && *argbuf) {
		char *fmt_on = "", *fmt_off = "";

		if (cfg->timestamp && tv)
			FPRINT_TIME(tv);

		if (!cfg->hide_tid)
			FPRINT_TID(tid);

		if (indent_depth && cfg->indent_sym)
			fprintf(cfg->fout, "%.*s", indent_depth * cfg->indent_size, spaces);

		if (cfg->fmt_colors) {
			fmt_on = BOLDRED;
			fmt_off = RESET;
		}

		fprintf(cfg->fout, "[%s%s%s]\n", fmt_on, argbuf, fmt_off);
		fflush(NULL);
		return 0;
	}

	if (collapsed && !symname) {
		(*nsuppressed)++;
		return 0;
	}

	if (collapsed == COLLAPSED_NESTED) {
		int demangled = 0;

		if (cfg->demangle)
			DEMANGLE(symname, demangled);

		PRINT_DATA(buffered, "%s()", symname);

		if (demangled)
			XFREE((char *)symname);

		if (outbuf) {
			buffer_output_data(tid, outbuf, indent_depth, 1);
			XFREE(outbuf);
		}

		return 0;
	}

	if (cfg->timestamp && tv) {
		if (buffered)
			SPRINT_TIME(tv);
		else
			FPRINT_TIME(tv);
	}

	/* Print thread ID */
	if (!cfg->hide_tid) {
		if (buffered)
			SPRINT_TID(tid);
		else
			FPRINT_TID(tid);
	}

	/* Print indentation. */
	if (indent_depth && cfg->indent_sym) {

		if (cfg->fmt_colors)
			cur_color = color_table[indent_depth % (sizeof(color_table)/sizeof(color_table[0]))];

		PRINT_DATA(buffered, "%.*s", indent_depth * cfg->indent_size, spaces);
	}

	/* Demangle the symbol if needed */
	if (cfg->demangle)
		DEMANGLE(symname, demangled);

	if (lt_sh(cfg, lib_short)) {
		char *rptr = strrchr(lib_to, '/');

		if (rptr)
			lib_to = ++rptr;
	}

	if (collapsed == COLLAPSED_BARE)
		end_line = "";
	else if (collapsed == COLLAPSED_TERSE)
		end_line = "";

	/* Print the symbol and arguments. */
	if (cur_color) {
		if (*argbuf)
			PRINT_DATA(buffered, "%s%s%s%s(%s%s%s) [%s] %s",
				BOLD, cur_color, symname, RESET, cur_color, argbuf, RESET, lib_to, end_line);
		else
			PRINT_DATA(buffered, "%s%s%s [%s] %c\n",
						cur_color, symname, RESET, lib_to,
						cfg->braces ? '{' : ' ');
	} else {
		if (*argbuf)
			PRINT_DATA(buffered, "%s(%s) [%s] %s", symname, argbuf, lib_to, end_line);
		else
			PRINT_DATA(buffered, "%s [%s] %c\n",
						symname, lib_to,
						cfg->braces ? '{' : ' ');
	}

	if (demangled)
		XFREE((char*) symname);

	/* Print arguments' details. */
	if (cfg->args_detailed && *argdbuf)
		PRINT_DETAILS(buffered, argdbuf);

	fflush(NULL);

	if (outbuf) {
		buffer_output_data(tid, outbuf, indent_depth, 0);
		XFREE(outbuf);
	}

	return 0;
}

int lt_out_exit(struct lt_config_shared *cfg,
			struct timeval *tv, pid_t tid,
			int indent_depth, int collapsed,
			const char *symname, char *lib_to,
			char *argbuf, char *argdbuf,
			size_t *nsuppressed)
{
	const char *cur_color = NULL;
	char *prefix;
	int demangled = 0;

	if ((prefix = pop_output_data(tid))) {

		if (*nsuppressed) {
			char *label, *eol = "", *style_on = "", *style_off = "";

			if (prefix[strlen(prefix)-1] == '\n') {
				prefix[strlen(prefix)-1] = 0;
				eol = "\n";
			}

			label = *nsuppressed == 1 ? "suppression" : "suppressions";

			if (cfg->fmt_colors) {
				style_on = INVERT;
				style_off = INVOFF;
			}

			fprintf(cfg->fout, "%s %s{%zu %s}%s%s", prefix, style_on, *nsuppressed, label, style_off, eol);
		} else
			fprintf(cfg->fout, "%s", prefix);

		XFREE(prefix);
		*nsuppressed = 0;
	}

	if (!*argbuf && (!cfg->braces))
		return 0;

	if (cfg->timestamp && tv)
		FPRINT_TIME(tv);

	/* Print thread ID */
	if ((!cfg->hide_tid) && (collapsed <= COLLAPSED_BASIC))
		FPRINT_TID(tid);

	/* Print indentation. */
	if (indent_depth && cfg->indent_sym) {

		if (cfg->fmt_colors)
			cur_color = color_table[indent_depth % (sizeof(color_table)/sizeof(color_table[0]))];

		if (collapsed <= COLLAPSED_BASIC)
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
	if (collapsed <= COLLAPSED_BASIC) {
		if (cur_color)
			fprintf(cfg->fout, "} %s%s%s%s%s\n", BOLD, cur_color, symname, RESET, argbuf);
		else
			fprintf(cfg->fout, "} %s%s\n", symname, argbuf);
	} else if (collapsed >= COLLAPSED_TERSE) {
		if (cur_color)
			fprintf(cfg->fout, "%s%s%s%s\n", BOLD, cur_color, argbuf, RESET);
		else
			fprintf(cfg->fout, "%s\n", argbuf);
	}

	if (demangled)
		XFREE((char*) symname);

	/* Print arguments' details. */
	if (cfg->args_detailed && *argdbuf)
		print_details(cfg, argdbuf);

	fflush(NULL);
	return 0;
}
