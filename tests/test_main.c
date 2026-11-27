/* SPDX-License-Identifier: BSD-2-Clause
 * Test runner entry point.
 */
#include "test_util.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	const char *vectors = "tests/vectors/vectors.json";
	if (argc > 1)
		vectors = argv[1];

	int total = 0, passed_suites = 0, suites = 0;

	struct suite { const char *name; bool (*fn)(void *, int *); void *arg; };
	/* Simple direct invocation keeps output readable. */
	int n = 0;
	bool ok;

	ok = run_kdf_tests(vectors, &n);
	printf("[%s] KDF conformance (%d checks)\n", ok ? "PASS" : "FAIL", n);
	total += n; suites++; passed_suites += ok;

	n = 0;
	ok = run_mac_tests(vectors, &n);
	printf("[%s] segment MAC + SNE participation (%d checks)\n",
	       ok ? "PASS" : "FAIL", n);
	total += n; suites++; passed_suites += ok;

	n = 0;
	ok = run_sne_tests(vectors, &n);
	printf("[%s] SNE rollover semantics (%d checks)\n",
	       ok ? "PASS" : "FAIL", n);
	total += n; suites++; passed_suites += ok;

	n = 0;
	ok = run_rollover_tests(&n);
	printf("[%s] hitless rollover state machine (%d checks)\n",
	       ok ? "PASS" : "FAIL", n);
	total += n; suites++; passed_suites += ok;

	n = 0;
	ok = run_keystore_tests(&n);
	printf("[%s] MKT keystore (%d checks)\n", ok ? "PASS" : "FAIL", n);
	total += n; suites++; passed_suites += ok;

	printf("\n%d/%d suites passed, %d total assertions\n",
	       passed_suites, suites, total);
	return passed_suites == suites ? 0 : 1;
}
