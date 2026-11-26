#include "tcp_ao.h"

#include <string.h>

const char *ao_strerror(int status)
{
	switch (status) {
	case AO_OK: return "ok";
	case AO_EINVAL: return "invalid argument";
	case AO_ENOMEM: return "out of memory";
	case AO_ENOTFOUND: return "key or object not found";
	case AO_EEXIST: return "duplicate key identifier";
	case AO_EVERIFY: return "TCP-AO authentication failed";
	case AO_EUNSUPPORTED: return "unsupported algorithm or operation";
	case AO_EAGAIN: return "retry later";
	case AO_ESTATE: return "invalid state";
	case AO_EOVERFLOW: return "buffer or table overflow";
	case AO_EIO: return "I/O error";
	default: return "unknown error";
	}
}

int ao_addr_ipv4(ao_addr_t *a, const uint8_t bytes[4], uint16_t port)
{
	if (!a || !bytes)
		return AO_EINVAL;
	memset(a, 0, sizeof(*a));
	a->family = AO_FAMILY_IPV4;
	memcpy(a->addr, bytes, 4);
	a->port = port;
	a->prefix = 32;
	return AO_OK;
}

int ao_addr_ipv6(ao_addr_t *a, const uint8_t bytes[16], uint16_t port)
{
	if (!a || !bytes)
		return AO_EINVAL;
	memset(a, 0, sizeof(*a));
	a->family = AO_FAMILY_IPV6;
	memcpy(a->addr, bytes, 16);
	a->port = port;
	a->prefix = 128;
	return AO_OK;
}

int ao_addr_set_prefix(ao_addr_t *a, uint8_t prefix)
{
	uint8_t max_prefix;

	if (!a)
		return AO_EINVAL;
	max_prefix = a->family == AO_FAMILY_IPV4 ? 32 : 128;
	if (prefix > max_prefix)
		return AO_EINVAL;
	a->prefix = prefix;
	return AO_OK;
}

static int prefix_match(const uint8_t *a, const uint8_t *b, uint8_t prefix,
			size_t bytes)
{
	size_t full = prefix / 8;
	int rem = prefix % 8;

	if (full > bytes)
		return 0;
	if (full && memcmp(a, b, full) != 0)
		return 0;
	if (rem && full < bytes) {
		uint8_t mask = (uint8_t)(0xffU << (8 - rem));
		if ((a[full] & mask) != (b[full] & mask))
			return 0;
	}
	return 1;
}

int ao_addr_equal(const ao_addr_t *a, const ao_addr_t *b)
{
	size_t bytes;

	if (!a || !b || a->family != b->family)
		return 0;
	if (a->port != b->port)
		return 0;
	bytes = a->family == AO_FAMILY_IPV4 ? 4 : 16;
	return prefix_match(a->addr, b->addr, a->prefix, bytes);
}

/* Exact equality is used for actual connection tuples and tests. */
int ao_tuple_equal(const ao_tuple_t *a, const ao_tuple_t *b)
{
	if (!a || !b)
		return 0;
	if (a->local.family != b->local.family ||
	    a->remote.family != b->remote.family)
		return 0;
	if (a->local.port != b->local.port || a->remote.port != b->remote.port)
		return 0;
	if (memcmp(a->local.addr, b->local.addr,
		   a->local.family == AO_FAMILY_IPV4 ? 4 : 16) != 0)
		return 0;
	if (memcmp(a->remote.addr, b->remote.addr,
		   a->remote.family == AO_FAMILY_IPV4 ? 4 : 16) != 0)
		return 0;
	return 1;
}
