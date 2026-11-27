/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Minimal JSON subset reader for the generated test vectors. Handles
 * flat objects, nested arrays of flat objects, hex strings and numbers
 * — enough for vectors.json, nothing more. Kept dependency-free.
 */
#ifndef TEST_JSON_H
#define TEST_JSON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

struct json_val;

const struct json_val *json_load(const char *path);
void json_free(const struct json_val *root);

const struct json_val *json_get(const struct json_val *obj, const char *key);
size_t json_arr_len(const struct json_val *arr);
const struct json_val *json_arr_get(const struct json_val *arr, size_t i);

const char *json_str(const struct json_val *v);
long long json_int(const struct json_val *v);

/* hex string -> bytes; returns length or -1. */
int json_hex(const struct json_val *v, uint8_t *out, size_t outcap);

#define TEST_FAIL(...) do { \
	fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); \
	return false; \
} while (0)

#define CHECK(cond) do { if (!(cond)) TEST_FAIL("check failed: %s", #cond); } while (0)

bool run_kdf_tests(const char *vector_path, int *total);
bool run_mac_tests(const char *vector_path, int *total);
bool run_sne_tests(const char *vector_path, int *total);
bool run_rollover_tests(int *total);
bool run_keystore_tests(int *total);

#ifdef __cplusplus
}
#endif
#endif
