#include "tcp_ao_linux.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <arpa/inet.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#define AO_UAPI_TCP_MD5SIG 14
#define AO_UAPI_TCP_MD5SIG_EXT 32
#define AO_UAPI_TCP_AO_ADD_KEY 38
#define AO_UAPI_TCP_AO_DEL_KEY 39
#define AO_UAPI_TCP_AO_INFO 40

#define AO_UAPI_TCP_AO_KEYF_IFINDEX (1u << 0)
#define AO_UAPI_TCP_AO_KEYF_EXCLUDE_OPT (1u << 1)
#define AO_UAPI_TCP_MD5SIG_FLAG_PREFIX 0x1u
#define AO_UAPI_TCP_MD5SIG_FLAG_IFINDEX 0x2u

struct ao_uapi_ao_add {
	struct sockaddr_storage addr;
	char alg_name[64];
	int32_t ifindex;
	uint32_t set_current : 1,
		 set_rnext : 1,
		 reserved : 30;
	uint16_t reserved2;
	uint8_t prefix;
	uint8_t sndid;
	uint8_t rcvid;
	uint8_t maclen;
	uint8_t keyflags;
	uint8_t keylen;
	uint8_t key[80];
} __attribute__((aligned(8)));

struct ao_uapi_ao_del {
	struct sockaddr_storage addr;
	int32_t ifindex;
	uint32_t set_current : 1,
		 set_rnext : 1,
		 del_async : 1,
		 reserved : 29;
	uint16_t reserved2;
	uint8_t prefix;
	uint8_t sndid;
	uint8_t rcvid;
	uint8_t current_key;
	uint8_t rnext;
	uint8_t keyflags;
} __attribute__((aligned(8)));

struct ao_uapi_ao_info {
	uint32_t set_current : 1,
		 set_rnext : 1,
		 ao_required : 1,
		 set_counters : 1,
		 accept_icmps : 1,
		 reserved : 27;
	uint16_t reserved2;
	uint8_t current_key;
	uint8_t rnext;
	uint64_t pkt_good;
	uint64_t pkt_bad;
	uint64_t pkt_key_not_found;
	uint64_t pkt_ao_required;
	uint64_t pkt_dropped_icmp;
} __attribute__((aligned(8)));

struct ao_uapi_md5sig {
	struct sockaddr_storage addr;
	uint8_t flags;
	uint8_t prefixlen;
	uint16_t keylen;
	int32_t ifindex;
	uint8_t key[80];
};

#ifdef __linux__
static int map_sockerr(void)
{
	if (errno == ENOPROTOOPT || errno == EOPNOTSUPP)
		return AO_EUNSUPPORTED;
	if (errno == EEXIST || errno == EADDRINUSE)
		return AO_EEXIST;
	if (errno == EINVAL)
		return AO_EINVAL;
	if (errno == ENOMEM)
		return AO_ENOMEM;
	return AO_EIO;
}

static void fill_addr(const ao_addr_t *a, struct sockaddr_storage *ss)
{
	memset(ss, 0, sizeof(*ss));
	if (!a || a->family == AO_FAMILY_UNSPEC) {
		ss->ss_family = AF_UNSPEC;
		return;
	}
	if (a->family == AO_FAMILY_IPV4) {
		struct sockaddr_in *sin = (struct sockaddr_in *)ss;
		sin->sin_family = AF_INET;
		sin->sin_port = htons(a->port);
		memcpy(&sin->sin_addr, a->addr, 4);
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(a->port);
		memcpy(&sin6->sin6_addr, a->addr, 16);
	}
}

static const char *alg_name(enum ao_alg alg)
{
	switch (alg) {
	case AO_ALG_HMAC_SHA1_96:
		return "hmac(sha1)";
	case AO_ALG_AES_128_CMAC_96:
		return "cmac(aes)";
	case AO_ALG_HMAC_SHA256_96:
		return "hmac(sha256)";
	}
	return NULL;
}
#endif /* __linux__ */

int ao_linux_probe(int fd)
{
#ifdef __linux__
	struct ao_uapi_ao_info info;
	socklen_t len = sizeof(info);
	int own_fd = -1;
	int rc;

	if (fd < 0) {
		own_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (own_fd < 0)
			return map_sockerr();
		fd = own_fd;
	}

	memset(&info, 0, sizeof(info));
	if (getsockopt(fd, IPPROTO_TCP, AO_UAPI_TCP_AO_INFO,
		       &info, &len) != 0)
		rc = map_sockerr();
	else
		rc = AO_OK;
	if (own_fd >= 0)
		close(own_fd);
	return rc;
#else
	(void)fd;
	return AO_EUNSUPPORTED;
#endif
}

int ao_linux_add_mkt(int fd, const ao_mkt_t *mkt,
		     int set_current, int set_rnext)
{
#ifdef __linux__
	struct ao_uapi_ao_add arg;
	const char *name;

	if (fd < 0 || !mkt || mkt->key_len == 0)
		return AO_EINVAL;
	name = alg_name(mkt->alg);
	if (!name)
		return AO_EUNSUPPORTED;

	memset(&arg, 0, sizeof(arg));
	fill_addr(&mkt->match.remote, &arg.addr);
	strncpy(arg.alg_name, name, sizeof(arg.alg_name) - 1);
	arg.ifindex = (int32_t)mkt->match.remote.ifindex;
	arg.set_current = set_current ? 1 : 0;
	arg.set_rnext = set_rnext ? 1 : 0;
	arg.prefix = mkt->match.remote.prefix;
	arg.sndid = mkt->send_id;
	arg.rcvid = mkt->recv_id;
	arg.maclen = mkt->mac_len ? mkt->mac_len :
		(mkt->alg == AO_ALG_HMAC_SHA1_96 ? 12 : 12);
	arg.keylen = mkt->key_len;
	memcpy(arg.key, mkt->master_key, mkt->key_len);
	if (mkt->match.remote.ifindex)
		arg.keyflags |= AO_UAPI_TCP_AO_KEYF_IFINDEX;
	if (mkt->exclude_options)
		arg.keyflags |= AO_UAPI_TCP_AO_KEYF_EXCLUDE_OPT;

	if (setsockopt(fd, IPPROTO_TCP, AO_UAPI_TCP_AO_ADD_KEY,
		       &arg, sizeof(arg)) != 0)
		return map_sockerr();
	return AO_OK;
#else
	(void)fd; (void)mkt; (void)set_current; (void)set_rnext;
	return AO_EUNSUPPORTED;
#endif
}

int ao_linux_apply_table(int fd, const ao_table_t *table)
{
	ao_mkt_t *items = NULL;
	size_t count = 0, i;
	int rc;

	if (!table)
		return AO_EINVAL;
	rc = ao_table_snapshot(table, &items, &count);
	if (rc != AO_OK)
		return rc;

	for (i = 0; i < count; ++i) {
		rc = ao_linux_add_mkt(fd, &items[i], 0, 0);
		if (rc != AO_OK) {
			ao_table_snapshot_free(items, count);
			return rc;
		}
	}
	ao_table_snapshot_free(items, count);
	return AO_OK;
}

int ao_linux_del_mkt(int fd, const ao_mkt_t *mkt)
{
#ifdef __linux__
	struct ao_uapi_ao_del arg;

	if (fd < 0 || !mkt)
		return AO_EINVAL;
	memset(&arg, 0, sizeof(arg));
	fill_addr(&mkt->match.remote, &arg.addr);
	arg.ifindex = (int32_t)mkt->match.remote.ifindex;
	arg.prefix = mkt->match.remote.prefix;
	arg.sndid = mkt->send_id;
	arg.rcvid = mkt->recv_id;
	if (mkt->match.remote.ifindex)
		arg.keyflags |= AO_UAPI_TCP_AO_KEYF_IFINDEX;

	if (setsockopt(fd, IPPROTO_TCP, AO_UAPI_TCP_AO_DEL_KEY,
		       &arg, sizeof(arg)) != 0)
		return map_sockerr();
	return AO_OK;
#else
	(void)fd; (void)mkt;
	return AO_EUNSUPPORTED;
#endif
}

int ao_linux_force_del_mkt(int fd, const ao_mkt_t *old_mkt,
			   uint8_t replacement_current_send_id,
			   uint8_t replacement_rnext_recv_id)
{
#ifdef __linux__
	struct ao_uapi_ao_del arg;
	int rc;

	if (fd < 0 || !old_mkt)
		return AO_EINVAL;
	memset(&arg, 0, sizeof(arg));
	fill_addr(&old_mkt->match.remote, &arg.addr);
	arg.sndid = old_mkt->send_id;
	arg.rcvid = old_mkt->recv_id;
	arg.prefix = old_mkt->match.remote.prefix;
	arg.set_current = 1;
	arg.set_rnext = 1;
	arg.current_key = replacement_current_send_id;
	arg.rnext = replacement_rnext_recv_id;
	rc = setsockopt(fd, IPPROTO_TCP, AO_UAPI_TCP_AO_DEL_KEY,
			&arg, sizeof(arg));
	return rc == 0 ? AO_OK : map_sockerr();
#else
	(void)fd; (void)old_mkt;
	(void)replacement_current_send_id;
	(void)replacement_rnext_recv_id;
	return AO_EUNSUPPORTED;
#endif
}

int ao_linux_set_rnext(int fd, uint8_t rnext_recv_id)
{
#ifdef __linux__
	struct ao_uapi_ao_info arg;

	memset(&arg, 0, sizeof(arg));
	arg.set_rnext = 1;
	arg.rnext = rnext_recv_id;
	if (setsockopt(fd, IPPROTO_TCP, AO_UAPI_TCP_AO_INFO,
		       &arg, sizeof(arg)) != 0)
		return map_sockerr();
	return AO_OK;
#else
	(void)fd; (void)rnext_recv_id;
	return AO_EUNSUPPORTED;
#endif
}

int ao_linux_set_current(int fd, uint8_t current_send_id)
{
#ifdef __linux__
	struct ao_uapi_ao_info arg;

	memset(&arg, 0, sizeof(arg));
	arg.set_current = 1;
	arg.current_key = current_send_id;
	if (setsockopt(fd, IPPROTO_TCP, AO_UAPI_TCP_AO_INFO,
		       &arg, sizeof(arg)) != 0)
		return map_sockerr();
	return AO_OK;
#else
	(void)fd; (void)current_send_id;
	return AO_EUNSUPPORTED;
#endif
}

int ao_linux_get_info(int fd, ao_linux_info_t *info)
{
#ifdef __linux__
	struct ao_uapi_ao_info arg;
	socklen_t len = sizeof(arg);

	if (!info)
		return AO_EINVAL;
	memset(&arg, 0, sizeof(arg));
	if (getsockopt(fd, IPPROTO_TCP, AO_UAPI_TCP_AO_INFO,
		       &arg, &len) != 0)
		return map_sockerr();
	memset(info, 0, sizeof(*info));
	info->current_send_id = arg.current_key;
	info->rnext_recv_id = arg.rnext;
	info->pkt_good = arg.pkt_good;
	info->pkt_bad = arg.pkt_bad;
	info->pkt_key_not_found = arg.pkt_key_not_found;
	info->pkt_ao_required = arg.pkt_ao_required;
	return AO_OK;
#else
	(void)fd; (void)info;
	return AO_EUNSUPPORTED;
#endif
}

int ao_linux_add_md5(int fd, const ao_addr_t *peer,
		     const uint8_t *key, size_t key_len)
{
#ifdef __linux__
	struct ao_uapi_md5sig arg;
	int rc;

	if (fd < 0 || !peer || !key || key_len == 0 || key_len > 80)
		return AO_EINVAL;
	memset(&arg, 0, sizeof(arg));
	fill_addr(peer, &arg.addr);
	arg.keylen = (uint16_t)key_len;
	memcpy(arg.key, key, key_len);
	if (peer->prefix) {
		arg.flags |= AO_UAPI_TCP_MD5SIG_FLAG_PREFIX;
		arg.prefixlen = peer->prefix;
	}
	if (peer->ifindex) {
		arg.flags |= AO_UAPI_TCP_MD5SIG_FLAG_IFINDEX;
		arg.ifindex = (int32_t)peer->ifindex;
	}

	rc = setsockopt(fd, IPPROTO_TCP, AO_UAPI_TCP_MD5SIG_EXT,
			&arg, sizeof(arg));
	if (rc != 0 && errno == ENOPROTOOPT) {
		rc = setsockopt(fd, IPPROTO_TCP, AO_UAPI_TCP_MD5SIG,
				&arg, sizeof(arg));
	}
	return rc == 0 ? AO_OK : map_sockerr();
#else
	(void)fd; (void)peer; (void)key; (void)key_len;
	return AO_EUNSUPPORTED;
#endif
}

int ao_linux_send_queue_bytes(int fd, size_t *bytes)
{
#ifdef __linux__
	int queued = 0;

	if (!bytes)
		return AO_EINVAL;
	if (ioctl(fd, SIOCOUTQ, &queued) != 0)
		return map_sockerr();
	*bytes = (size_t)queued;
	return AO_OK;
#else
	(void)fd;
	if (bytes)
		*bytes = 0;
	return AO_EUNSUPPORTED;
#endif
}
