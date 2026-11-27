/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Linux TCP_AO setsockopt adapter. Compiled only on Linux; non-Linux
 * builds link kernel_stub.c so the portable layers stay testable.
 */
#ifdef __linux__

#include "tcpao/kernel.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/tcp.h>

#ifndef TCP_AO_ADD_KEY
#error "TCP_AO uAPI missing: need kernel headers >= 6.10 (include/uapi/linux/tcp.h)"
#endif

bool tcpao_kernel_supported(void)
{
	/* Probe with an empty TCP_AO_INFO getsockopt on a fresh socket:
	 * EOPNOTSUPP/ENOPROTOOPT means the kernel lacks CONFIG_TCP_AO. */
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return false;
	struct tcp_ao_info_opt opt;
	memset(&opt, 0, sizeof(opt));
	socklen_t len = sizeof(opt);
	int rc = getsockopt(fd, IPPROTO_TCP, TCP_AO_INFO, &opt, &len);
	bool ok = (rc == 0 || errno != ENOPROTOOPT && errno != EOPNOTSUPP);
	close(fd);
	return ok;
}

static const char *alg_to_kernel(enum tcpao_alg alg)
{
	switch (alg) {
	case TCPAO_ALG_HMAC_SHA1_96:	return "hmac(sha1)";
	case TCPAO_ALG_AES_128_CMAC_96:	return "cmac(aes)";
	case TCPAO_ALG_HMAC_SHA256:	return "hmac(sha256)";
	}
	return NULL;
}

int tcpao_kernel_add_key(int fd, const struct tcpao_mkt *mkt,
			 bool set_current, bool set_rnext)
{
	struct tcp_ao_add opt;
	memset(&opt, 0, sizeof(opt));

	size_t addrlen = mkt->peer.ss_family == AF_INET6 ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	memcpy(&opt.addr, &mkt->peer, addrlen);

	const char *alg = alg_to_kernel(mkt->alg);
	if (!alg)
		return -EINVAL;
	strncpy(opt.alg_name, alg, sizeof(opt.alg_name) - 1);

	opt.ifindex	= mkt->ifindex;
	opt.set_current	= set_current ? 1 : 0;
	opt.set_rnext	= set_rnext ? 1 : 0;
	opt.prefix	= mkt->prefix;
	opt.sndid	= mkt->sndid;
	opt.rcvid	= mkt->rcvid;
	opt.maclen	= mkt->maclen;
	opt.keyflags	= mkt->exclude_options ? TCP_AO_KEYF_EXCLUDE_OPT : 0;
	opt.keylen	= mkt->keylen;
	memcpy(opt.key, mkt->key, mkt->keylen);

	if (setsockopt(fd, IPPROTO_TCP, TCP_AO_ADD_KEY, &opt, sizeof(opt)))
		return -errno;
	return 0;
}

int tcpao_kernel_del_key(int fd, const struct tcpao_mkt *mkt)
{
	struct tcp_ao_del opt;
	memset(&opt, 0, sizeof(opt));
	size_t addrlen = mkt->peer.ss_family == AF_INET6 ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	memcpy(&opt.addr, &mkt->peer, addrlen);
	opt.ifindex	= mkt->ifindex;
	opt.prefix	= mkt->prefix;
	opt.sndid	= mkt->sndid;
	opt.rcvid	= mkt->rcvid;
	opt.keyflags	= mkt->exclude_options ? TCP_AO_KEYF_EXCLUDE_OPT : 0;

	if (setsockopt(fd, IPPROTO_TCP, TCP_AO_DEL_KEY, &opt, sizeof(opt)))
		return -errno;
	return 0;
}

int tcpao_kernel_force_del_key(int fd, const struct tcpao_mkt *victim,
			       uint8_t replacement_current,
			       uint8_t replacement_rnext,
			       bool set_current, bool set_rnext)
{
	struct tcp_ao_del opt;
	memset(&opt, 0, sizeof(opt));
	size_t addrlen = victim->peer.ss_family == AF_INET6 ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	memcpy(&opt.addr, &victim->peer, addrlen);
	opt.ifindex	= victim->ifindex;
	opt.prefix	= victim->prefix;
	opt.sndid	= victim->sndid;
	opt.rcvid	= victim->rcvid;
	opt.keyflags	= victim->exclude_options ? TCP_AO_KEYF_EXCLUDE_OPT : 0;
	opt.set_current	= set_current ? 1 : 0;
	opt.set_rnext	= set_rnext ? 1 : 0;
	opt.current_key	= replacement_current;
	opt.rnext	= replacement_rnext;

	if (setsockopt(fd, IPPROTO_TCP, TCP_AO_DEL_KEY, &opt, sizeof(opt)))
		return -errno;
	return 0;
}

int tcpao_kernel_set_pointers(int fd, int current_keyid, int rnext_keyid)
{
	struct tcp_ao_info_opt opt;
	memset(&opt, 0, sizeof(opt));
	if (current_keyid >= 0) {
		opt.set_current = 1;
		opt.current_key = (uint8_t)current_keyid;
	}
	if (rnext_keyid >= 0) {
		opt.set_rnext = 1;
		opt.rnext = (uint8_t)rnext_keyid;
	}
	if (setsockopt(fd, IPPROTO_TCP, TCP_AO_INFO, &opt, sizeof(opt)))
		return -errno;
	return 0;
}

int tcpao_kernel_get_info(int fd, struct tcpao_ao_info *out)
{
	struct tcp_ao_info_opt opt;
	memset(&opt, 0, sizeof(opt));
	socklen_t len = sizeof(opt);
	if (getsockopt(fd, IPPROTO_TCP, TCP_AO_INFO, &opt, &len))
		return -errno;
	out->current_key	= opt.current_key;
	out->rnext		= opt.rnext;
	out->pkt_good		= opt.pkt_good;
	out->pkt_bad		= opt.pkt_bad;
	out->pkt_key_not_found	= opt.pkt_key_not_found;
	out->pkt_ao_required	= opt.pkt_ao_required;
	return 0;
}

int tcpao_kernel_set_required(int fd, bool required)
{
	struct tcp_ao_info_opt opt;
	memset(&opt, 0, sizeof(opt));
	opt.ao_required = required ? 1 : 0;
	if (setsockopt(fd, IPPROTO_TCP, TCP_AO_INFO, &opt, sizeof(opt)))
		return -errno;
	return 0;
}

int tcpao_kernel_get_keys(int fd, const struct sockaddr *peer,
			  struct tcpao_mkt *out, size_t cap, size_t *n)
{
	/* The uAPI returns one struct tcp_ao_getsockopt *per matching key*
	 * in a caller-sized array; opt.nkeys on entry is the buffer size in
	 * bytes and on exit the number of matched keys. This wrapper performs
	 * a single-record query (cap >= 1) and reports the total match count
	 * so callers can detect truncation. A full dump needs a
	 * struct tcp_ao_getsockopt array, as the kernel selftests do. */
	struct tcp_ao_getsockopt opt;
	memset(&opt, 0, sizeof(opt));
	size_t addrlen = peer->sa_family == AF_INET6 ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	memcpy(&opt.addr, peer, addrlen);
	opt.get_all = 1;
	opt.nkeys = sizeof(opt);	/* room for one record, in bytes */
	socklen_t len = sizeof(opt);
	if (getsockopt(fd, IPPROTO_TCP, TCP_AO_GET_KEYS, &opt, &len))
		return -errno;

	size_t matched = opt.nkeys;
	if (n)
		*n = matched;
	if (cap && out && matched) {
		memset(out, 0, sizeof(*out));
		memcpy(&out->peer, &opt.addr, addrlen);
		out->sndid	= opt.sndid;
		out->rcvid	= opt.rcvid;
		out->prefix	= opt.prefix;
		out->maclen	= opt.maclen;
		out->exclude_options = (opt.keyflags & TCP_AO_KEYF_EXCLUDE_OPT);
		out->keylen	= opt.keylen;
		out->ifindex	= opt.ifindex;
		memcpy(out->key, opt.key, opt.keylen);
	}
	return 0;
}

/* ---- RFC 2385 MD5 coexistence ------------------------------------------- */

#include <linux/tcp.h>
#ifndef TCP_MD5SIG_EXT
#define TCP_MD5SIG_EXT		32
struct tcp_md5sig_ext {
	struct sockaddr_storage tcpm_addr;
	__u8			tcpm_flags;
	__u8			tcpm_prefixlen;
	__u16			tcpm_keylen;
	int			tcpm_ifindex;
	__u8			tcpm_key[80];
};
#define TCP_MD5SIG_FLAG_PREFIX	0x1
#endif

int tcpao_md5_listener_add(int fd, const struct tcpao_md5_key *k)
{
	struct tcp_md5sig_ext sig;
	memset(&sig, 0, sizeof(sig));
	size_t addrlen = k->peer.ss_family == AF_INET6 ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	memcpy(&sig.tcpm_addr, &k->peer, addrlen);
	sig.tcpm_flags		= TCP_MD5SIG_FLAG_PREFIX;
	sig.tcpm_prefixlen	= k->prefix;
	sig.tcpm_keylen		= k->keylen;
	memcpy(sig.tcpm_key, k->key, k->keylen);
	if (setsockopt(fd, IPPROTO_TCP, TCP_MD5SIG_EXT, &sig, sizeof(sig)))
		return -errno;
	return 0;
}

int tcpao_md5_listener_del(int fd, const struct sockaddr *peer, uint8_t prefix)
{
	struct tcp_md5sig_ext sig;
	memset(&sig, 0, sizeof(sig));
	size_t addrlen = peer->sa_family == AF_INET6 ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	memcpy(&sig.tcpm_addr, peer, addrlen);
	sig.tcpm_flags		= TCP_MD5SIG_FLAG_PREFIX;
	sig.tcpm_prefixlen	= prefix;
	sig.tcpm_keylen		= 0;
	if (setsockopt(fd, IPPROTO_TCP, TCP_MD5SIG_EXT, &sig, sizeof(sig)))
		return -errno;
	return 0;
}

int tcpao_repair_get(int fd, struct tcpao_repair_state *out)
{
	struct tcp_ao_repair r;
	memset(&r, 0, sizeof(r));
	socklen_t len = sizeof(r);
	if (getsockopt(fd, IPPROTO_TCP, TCP_AO_REPAIR, &r, &len))
		return -errno;
	out->snt_isn = r.snt_isn;
	out->rcv_isn = r.rcv_isn;
	out->snd_sne = r.snd_sne;
	out->rcv_sne = r.rcv_sne;
	return 0;
}

int tcpao_repair_set(int fd, const struct tcpao_repair_state *in)
{
	struct tcp_ao_repair r = {
		.snt_isn = in->snt_isn,
		.rcv_isn = in->rcv_isn,
		.snd_sne = in->snd_sne,
		.rcv_sne = in->rcv_sne,
	};
	if (setsockopt(fd, IPPROTO_TCP, TCP_AO_REPAIR, &r, sizeof(r)))
		return -errno;
	return 0;
}

const char *tcpao_kernel_strerror(int err)
{
	switch (-err) {
	case EBUSY:		return "key is current/rnext or still in use";
	case EEXIST:		return "matching MKT with same SendID/RecvID exists";
	case EKEYEXPIRED:	return "goodbye key / key expired";
	case ENOKEY:		return "no matching MKT on socket";
	case EOPNOTSUPP:	return "TCP_AO not supported by this kernel";
	case EPERM:		return "cannot mix TCP-AO and TCP-MD5 on this peer";
	default:		return strerror(-err);
	}
}

#endif /* __linux__ */
