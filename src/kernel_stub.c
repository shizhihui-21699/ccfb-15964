/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Non-Linux stubs so the portable KDF/MAC/SNE/rollover code and all
 * unit tests compile and run on a development laptop. Every function
 * fails loudly: nothing here silently pretends to program a socket.
 */
#ifndef __linux__

#include "tcpao/kernel.h"

#include <errno.h>
#include <string.h>

bool tcpao_kernel_supported(void) { return false; }

int tcpao_kernel_add_key(int fd, const struct tcpao_mkt *mkt,
			 bool set_current, bool set_rnext)
{ (void)fd; (void)mkt; (void)set_current; (void)set_rnext; return -EOPNOTSUPP; }

int tcpao_kernel_del_key(int fd, const struct tcpao_mkt *mkt)
{ (void)fd; (void)mkt; return -EOPNOTSUPP; }

int tcpao_kernel_force_del_key(int fd, const struct tcpao_mkt *victim,
			       uint8_t a, uint8_t b, bool c, bool d)
{ (void)fd; (void)victim; (void)a; (void)b; (void)c; (void)d; return -EOPNOTSUPP; }

int tcpao_kernel_set_pointers(int fd, int a, int b)
{ (void)fd; (void)a; (void)b; return -EOPNOTSUPP; }

int tcpao_kernel_get_info(int fd, struct tcpao_ao_info *out)
{ (void)fd; (void)out; return -EOPNOTSUPP; }

int tcpao_kernel_set_required(int fd, bool required)
{ (void)fd; (void)required; return -EOPNOTSUPP; }

int tcpao_kernel_get_keys(int fd, const struct sockaddr *peer,
			  struct tcpao_mkt *out, size_t cap, size_t *n)
{ (void)fd; (void)peer; (void)out; (void)cap; (void)n; return -EOPNOTSUPP; }

int tcpao_md5_listener_add(int fd, const struct tcpao_md5_key *k)
{ (void)fd; (void)k; return -EOPNOTSUPP; }

int tcpao_md5_listener_del(int fd, const struct sockaddr *peer, uint8_t prefix)
{ (void)fd; (void)peer; (void)prefix; return -EOPNOTSUPP; }

int tcpao_repair_get(int fd, struct tcpao_repair_state *out)
{ (void)fd; (void)out; return -EOPNOTSUPP; }

int tcpao_repair_set(int fd, const struct tcpao_repair_state *in)
{ (void)fd; (void)in; return -EOPNOTSUPP; }

const char *tcpao_kernel_strerror(int err)
{ return strerror(-err); }

#endif
