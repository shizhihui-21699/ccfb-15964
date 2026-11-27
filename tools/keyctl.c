/* SPDX-License-Identifier: BSD-2-Clause
 *
 * bgp-ao-keyctl — operator-facing control for TCP-AO protected BGP
 * sessions. Talks to a running daemon's socket fds via a small unix
 * domain command socket in the real deployment; for bring-up and lab
 * use it can also drive a socket directly by fd (SCM_RIGHTS) or apply
 * keys to a fresh listener socket.
 *
 * Subcommands:
 *   key-add      <peer>/<plen> sndid rcvid alg maclen hexkey [--current]
 *   key-del      <peer>/<plen> sndid rcvid
 *   rotate       <peer>/<plen> old-snd old-rcv new-snd new-rcv hexkey
 *   info         print current_key/rnext and TCPAO* counters
 *   md5-add      <peer>/<plen> hexkey        (legacy coexistence)
 *   md5-del      <peer>/<plen>
 *   goodbye      <peer>/<plen> sndid rcvid
 *   require      on|off
 */
#include "tcpao/mkt.h"
#include "tcpao/kernel.h"
#include "tcpao/session.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static int parse_peer(const char *spec, struct sockaddr_storage *ss,
		      uint8_t *prefix)
{
	char buf[INET6_ADDRSTRLEN + 4];
	strncpy(buf, spec, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = 0;
	char *slash = strchr(buf, '/');
	if (slash) {
		*slash++ = 0;
		*prefix = (uint8_t)atoi(slash);
	} else {
		*prefix = 0;
	}
	memset(ss, 0, sizeof(*ss));
	if (strchr(buf, ':')) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
		s6->sin6_family = AF_INET6;
		if (inet_pton(AF_INET6, buf, &s6->sin6_addr) != 1)
			return -1;
		if (!*prefix)
			*prefix = 128;
	} else {
		struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
		s4->sin_family = AF_INET;
		if (inet_pton(AF_INET, buf, &s4->sin_addr) != 1)
			return -1;
		if (!*prefix)
			*prefix = 32;
	}
	return 0;
}

static int parse_hexkey(const char *hex, uint8_t *out, size_t cap,
			size_t *outlen)
{
	size_t n = strlen(hex);
	if (n % 2 || n / 2 > cap || n / 2 == 0)
		return -1;
	for (size_t i = 0; i < n; i += 2) {
		unsigned b;
		if (sscanf(hex + i, "%2x", &b) != 1)
			return -1;
		out[i / 2] = (uint8_t)b;
	}
	*outlen = n / 2;
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
		"usage: bgp-ao-keyctl [-f fd] <subcommand> args...\n"
		"  key-add PEER/PREFIX SNDID RCVID ALG MACLEN HEXKEY [--current]\n"
		"  key-del PEER/PREFIX SNDID RCVID\n"
		"  info\n"
		"  md5-add PEER/PREFIX HEXKEY\n"
		"  md5-del PEER/PREFIX\n"
		"  goodbye PEER/PREFIX SNDID RCVID\n"
		"  require on|off\n"
		"ALG: hmac-sha1-96 | aes-128-cmac-96 | hmac-sha256\n");
}

int main(int argc, char **argv)
{
	int opt;
	int fd = -1;
	while ((opt = getopt(argc, argv, "f:h")) != -1) {
		switch (opt) {
		case 'f': fd = atoi(optarg); break;
		default: usage(); return 2;
		}
	}
	if (optind >= argc) {
		usage();
		return 2;
	}
	const char *cmd = argv[optind++];
	int nleft = argc - optind;
	char **args = argv + optind;

	if (fd < 0) {
		fprintf(stderr,
			"note: -f fd required in standalone mode; in the "
			"daemon this CLI connects to its control socket\n");
		return 2;
	}

	if (!strcmp(cmd, "key-add") && nleft >= 6) {
		struct tcpao_mkt mkt = {0};
		if (parse_peer(args[0], &mkt.peer, &mkt.prefix))
			goto bad_peer;
		mkt.sndid = (uint8_t)atoi(args[1]);
		mkt.rcvid = (uint8_t)atoi(args[2]);
		if (tcpao_alg_from_name(args[3], &mkt.alg))
			goto bad_alg;
		mkt.maclen = (uint8_t)atoi(args[4]);
		size_t keylen = 0;
		if (parse_hexkey(args[5], mkt.key, sizeof(mkt.key),
				 &keylen) || keylen > UINT8_MAX)
			goto bad_key;
		mkt.keylen = (uint8_t)keylen;
		bool current = nleft >= 7 && !strcmp(args[6], "--current");
		int rc = tcpao_kernel_add_key(fd, &mkt, current, current);
		tcpao_explicit_bzero(mkt.key, sizeof(mkt.key));
		if (rc) { fprintf(stderr, "add failed: %s\n",
				  tcpao_kernel_strerror(rc)); return 1; }
		printf("key installed (sndid=%u rcvid=%u%s)\n",
		       mkt.sndid, mkt.rcvid, current ? ", current" : "");
		return 0;
	}

	if (!strcmp(cmd, "key-del") && nleft >= 3) {
		struct tcpao_mkt mkt = {0};
		if (parse_peer(args[0], &mkt.peer, &mkt.prefix))
			goto bad_peer;
		mkt.sndid = (uint8_t)atoi(args[1]);
		mkt.rcvid = (uint8_t)atoi(args[2]);
		int rc = tcpao_kernel_del_key(fd, &mkt);
		if (rc) { fprintf(stderr, "del failed: %s\n",
				  tcpao_kernel_strerror(rc)); return 1; }
		puts("key deleted");
		return 0;
	}

	if (!strcmp(cmd, "info") && nleft == 0) {
		struct tcpao_ao_info inf;
		int rc = tcpao_kernel_get_info(fd, &inf);
		if (rc) { fprintf(stderr, "info failed: %s\n",
				  tcpao_kernel_strerror(rc)); return 1; }
		printf("current_key=%u rnext=%u good=%llu bad=%llu "
		       "key_not_found=%llu ao_required_drops=%llu\n",
		       inf.current_key, inf.rnext,
		       (unsigned long long)inf.pkt_good,
		       (unsigned long long)inf.pkt_bad,
		       (unsigned long long)inf.pkt_key_not_found,
		       (unsigned long long)inf.pkt_ao_required);
		return 0;
	}

	if (!strcmp(cmd, "md5-add") && nleft >= 2) {
		struct tcpao_md5_key k = {0};
		if (parse_peer(args[0], &k.peer, &k.prefix))
			goto bad_peer;
		size_t md5len = 0;
		if (parse_hexkey(args[1], k.key, sizeof(k.key), &md5len) ||
		    md5len > UINT8_MAX)
			goto bad_key;
		k.keylen = (uint8_t)md5len;
		int rc = tcpao_md5_listener_add(fd, &k);
		tcpao_explicit_bzero(k.key, sizeof(k.key));
		if (rc) { fprintf(stderr, "md5 add failed: %s\n",
				  tcpao_kernel_strerror(rc)); return 1; }
		puts("legacy MD5 key installed on listener");
		return 0;
	}

	if (!strcmp(cmd, "md5-del") && nleft >= 1) {
		struct sockaddr_storage ss;
		uint8_t prefix;
		if (parse_peer(args[0], &ss, &prefix))
			goto bad_peer;
		int rc = tcpao_md5_listener_del(fd, (struct sockaddr *)&ss,
						prefix);
		if (rc) { fprintf(stderr, "md5 del failed: %s\n",
				  tcpao_kernel_strerror(rc)); return 1; }
		puts("legacy MD5 key removed");
		return 0;
	}

	if (!strcmp(cmd, "goodbye") && nleft >= 3) {
		struct sockaddr_storage ss;
		uint8_t prefix;
		if (parse_peer(args[0], &ss, &prefix))
			goto bad_peer;
		int rc = tcpao_install_goodbye(fd, (struct sockaddr *)&ss,
					       (uint8_t)atoi(args[1]),
					       (uint8_t)atoi(args[2]));
		if (rc) { fprintf(stderr, "goodbye failed: %s\n",
				  tcpao_kernel_strerror(rc)); return 1; }
		puts("goodbye key installed");
		return 0;
	}

	if (!strcmp(cmd, "require") && nleft == 1) {
		bool on = !strcmp(args[0], "on");
		if (strcmp(args[0], "on") && strcmp(args[0], "off"))
			goto usage_fail;
		int rc = tcpao_kernel_set_required(fd, on);
		if (rc) { fprintf(stderr, "require failed: %s\n",
				  tcpao_kernel_strerror(rc)); return 1; }
		printf("ao_required=%s\n", on ? "on" : "off");
		return 0;
	}

usage_fail:
	usage();
	return 2;
bad_peer:
	fprintf(stderr, "bad peer/prefix\n");
	return 2;
bad_alg:
	fprintf(stderr, "unknown algorithm\n");
	return 2;
bad_key:
	fprintf(stderr, "bad hex key (even number of hex chars, nonempty)\n");
	return 2;
}
