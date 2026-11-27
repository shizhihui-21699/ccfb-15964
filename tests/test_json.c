/* SPDX-License-Identifier: BSD-2-Clause
 * Minimal recursive-descent JSON parser (objects, arrays, strings,
 * integers, true/false/null). Sufficient for tests/vectors/vectors.json.
 */
#include "test_util.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum jtype { J_OBJ, J_ARR, J_STR, J_NUM, J_BOOL, J_NULL };

struct json_member { char *key; struct json_val *val; };

struct json_val {
	enum jtype type;
	union {
		struct { struct json_member *m; size_t n, cap; } o;
		struct { struct json_val **e; size_t n, cap; } a;
		char *s;
		long long i;
		int b;
	} u;
};

struct parser { const char *p; };

static void skip_ws(struct parser *p)
{
	while (*p->p && isspace((unsigned char)*p->p))
		p->p++;
}

static struct json_val *parse_val(struct parser *p);

static char *parse_string_raw(struct parser *p)
{
	skip_ws(p);
	if (*p->p != '"')
		return NULL;
	p->p++;
	size_t cap = 32, n = 0;
	char *s = malloc(cap);
	if (!s)
		return NULL;
	while (*p->p && *p->p != '"') {
		char c = *p->p++;
		if (c == '\\' && *p->p) {
			char e = *p->p++;
			switch (e) {
			case 'n': c = '\n'; break;
			case 't': c = '\t'; break;
			case 'r': c = '\r'; break;
			case '"': c = '"'; break;
			case '\\': c = '\\'; break;
			case '/': c = '/'; break;
			default: c = e; break;
			}
		}
		if (n + 1 >= cap) {
			cap *= 2;
			char *ns = realloc(s, cap);
			if (!ns) { free(s); return NULL; }
			s = ns;
		}
		s[n++] = c;
	}
	if (*p->p != '"') { free(s); return NULL; }
	p->p++;
	s[n] = 0;
	return s;
}

static struct json_val *new_val(enum jtype t)
{
	struct json_val *v = calloc(1, sizeof(*v));
	if (v)
		v->type = t;
	return v;
}

static struct json_val *parse_obj(struct parser *p)
{
	struct json_val *v = new_val(J_OBJ);
	p->p++; /* { */
	skip_ws(p);
	if (*p->p == '}') { p->p++; return v; }
	while (1) {
		char *key = parse_string_raw(p);
		if (!key) goto fail;
		skip_ws(p);
		if (*p->p++ != ':') { free(key); goto fail; }
		struct json_val *child = parse_val(p);
		if (!child) { free(key); goto fail; }
		if (v->u.o.n == v->u.o.cap) {
			size_t nc = v->u.o.cap ? v->u.o.cap * 2 : 4;
			struct json_member *nm = realloc(v->u.o.m,
							 nc * sizeof(*nm));
			if (!nm) { free(key); goto fail; }
			v->u.o.m = nm;
			v->u.o.cap = nc;
		}
		v->u.o.m[v->u.o.n++] = (struct json_member){ key, child };
		skip_ws(p);
		if (*p->p == ',') { p->p++; continue; }
		if (*p->p == '}') { p->p++; break; }
		goto fail;
	}
	return v;
fail:
	json_free(v);
	return NULL;
}

static struct json_val *parse_arr(struct parser *p)
{
	struct json_val *v = new_val(J_ARR);
	p->p++; /* [ */
	skip_ws(p);
	if (*p->p == ']') { p->p++; return v; }
	while (1) {
		struct json_val *child = parse_val(p);
		if (!child) goto fail;
		if (v->u.a.n == v->u.a.cap) {
			size_t nc = v->u.a.cap ? v->u.a.cap * 2 : 4;
			struct json_val **ne = realloc(v->u.a.e,
						       nc * sizeof(*ne));
			if (!ne) goto fail;
			v->u.a.e = ne;
			v->u.a.cap = nc;
		}
		v->u.a.e[v->u.a.n++] = child;
		skip_ws(p);
		if (*p->p == ',') { p->p++; continue; }
		if (*p->p == ']') { p->p++; break; }
		goto fail;
	}
	return v;
fail:
	json_free(v);
	return NULL;
}

static struct json_val *parse_val(struct parser *p)
{
	skip_ws(p);
	if (*p->p == '{') return parse_obj(p);
	if (*p->p == '[') return parse_arr(p);
	if (*p->p == '"') {
		char *s = parse_string_raw(p);
		if (!s) return NULL;
		struct json_val *v = new_val(J_STR);
		v->u.s = s;
		return v;
	}
	if (!strncmp(p->p, "true", 4)) {
		p->p += 4;
		struct json_val *v = new_val(J_BOOL);
		v->u.b = 1;
		return v;
	}
	if (!strncmp(p->p, "false", 5)) {
		p->p += 5;
		return new_val(J_BOOL);
	}
	if (!strncmp(p->p, "null", 4)) {
		p->p += 4;
		return new_val(J_NULL);
	}
	if (*p->p == '-' || isdigit((unsigned char)*p->p)) {
		char *end;
		long long n = strtoll(p->p, &end, 10);
		if (end == p->p)
			return NULL;
		p->p = end;
		struct json_val *v = new_val(J_NUM);
		v->u.i = n;
		return v;
	}
	return NULL;
}

const struct json_val *json_load(const char *path)
{
	FILE *f = fopen(path, "rb");
	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *buf = malloc(sz + 1);
	if (!buf) { fclose(f); return NULL; }
	if (fread(buf, 1, sz, f) != (size_t)sz) {
		free(buf); fclose(f); return NULL;
	}
	buf[sz] = 0;
	fclose(f);
	struct parser p = { buf };
	struct json_val *v = parse_val(&p);
	free(buf);
	return v;
}

static void val_free(struct json_val *v)
{
	if (!v) return;
	if (v->type == J_OBJ) {
		for (size_t i = 0; i < v->u.o.n; i++) {
			free(v->u.o.m[i].key);
			val_free(v->u.o.m[i].val);
		}
		free(v->u.o.m);
	} else if (v->type == J_ARR) {
		for (size_t i = 0; i < v->u.a.n; i++)
			val_free(v->u.a.e[i]);
		free(v->u.a.e);
	} else if (v->type == J_STR) {
		free(v->u.s);
	}
	free(v);
}

void json_free(const struct json_val *root)
{
	val_free((struct json_val *)(uintptr_t)root);
}

const struct json_val *json_get(const struct json_val *obj, const char *key)
{
	if (!obj || obj->type != J_OBJ)
		return NULL;
	for (size_t i = 0; i < obj->u.o.n; i++)
		if (!strcmp(obj->u.o.m[i].key, key))
			return obj->u.o.m[i].val;
	return NULL;
}

size_t json_arr_len(const struct json_val *arr)
{
	return (arr && arr->type == J_ARR) ? arr->u.a.n : 0;
}

const struct json_val *json_arr_get(const struct json_val *arr, size_t i)
{
	if (!arr || arr->type != J_ARR || i >= arr->u.a.n)
		return NULL;
	return arr->u.a.e[i];
}

const char *json_str(const struct json_val *v)
{
	return (v && v->type == J_STR) ? v->u.s : NULL;
}

long long json_int(const struct json_val *v)
{
	return (v && v->type == J_NUM) ? v->u.i : 0;
}

int json_hex(const struct json_val *v, uint8_t *out, size_t outcap)
{
	const char *s = json_str(v);
	if (!s)
		return -1;
	size_t len = strlen(s);
	if (len % 2 || len / 2 > outcap)
		return -1;
	for (size_t i = 0; i < len; i += 2) {
		unsigned b;
		if (sscanf(s + i, "%2x", &b) != 1)
			return -1;
		out[i / 2] = (uint8_t)b;
	}
	return (int)(len / 2);
}
