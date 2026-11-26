#include "tcp_ao.h"

#include <string.h>

size_t ao_option_total_len(uint8_t mac_len)
{
	return AO_OPTION_FIXED_LEN + mac_len;
}

int ao_option_build(uint8_t *buf, size_t cap, uint8_t key_id,
		    uint8_t rnext_id, const uint8_t *mac, uint8_t mac_len)
{
	size_t total = ao_option_total_len(mac_len);

	if (!buf || mac_len == 0 || mac_len > AO_MAX_MAC_LEN)
		return AO_EINVAL;
	if (cap < total || total > 255)
		return AO_EOVERFLOW;

	buf[0] = AO_OPTION_KIND;
	buf[1] = (uint8_t)total;
	buf[2] = key_id;
	buf[3] = rnext_id;
	if (mac)
		memcpy(buf + AO_OPTION_FIXED_LEN, mac, mac_len);
	else
		memset(buf + AO_OPTION_FIXED_LEN, 0, mac_len);
	return (int)total;
}

int ao_tcp_header_len(const uint8_t *tcp_segment, size_t tcp_len,
		      size_t *header_len)
{
	size_t len;

	if (!tcp_segment || !header_len || tcp_len < 20)
		return AO_EINVAL;
	len = (size_t)((tcp_segment[12] >> 4) & 0x0f) * 4;
	if (len < 20 || len > 60 || len > tcp_len)
		return AO_EINVAL;
	*header_len = len;
	return AO_OK;
}

int ao_option_parse(const uint8_t *tcp_segment, size_t tcp_len,
		    ao_option_t *opt)
{
	size_t off, header_len;
	int found = 0;
	int rc;

	if (!tcp_segment || !opt)
		return AO_EINVAL;
	rc = ao_tcp_header_len(tcp_segment, tcp_len, &header_len);
	if (rc != AO_OK)
		return rc;

	memset(opt, 0, sizeof(*opt));
	for (off = 20; off < header_len;) {
		uint8_t kind = tcp_segment[off];
		uint8_t optlen;

		if (kind == 0)
			break;
		if (kind == 1) {
			off++;
			continue;
		}
		if (off + 2 > header_len)
			return AO_EINVAL;
		optlen = tcp_segment[off + 1];
		if (optlen < 2 || off + optlen > header_len)
			return AO_EINVAL;

		if (kind == AO_OPTION_KIND) {
			if (optlen < AO_OPTION_FIXED_LEN)
				return AO_EINVAL;
			opt->option_offset = off;
			opt->key_id = tcp_segment[off + 2];
			opt->rnext_id = tcp_segment[off + 3];
			opt->mac_len = (uint8_t)(optlen - AO_OPTION_FIXED_LEN);
			if (opt->mac_len > AO_MAX_MAC_LEN)
				return AO_EINVAL;
			opt->mac = tcp_segment + off + AO_OPTION_FIXED_LEN;
			found = 1;
			break;
		}
		off += optlen;
	}

	return found ? AO_OK : AO_ENOTFOUND;
}
