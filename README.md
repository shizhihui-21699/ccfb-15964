# BGP 不断话 TCP-AO 主密钥与滚动换钥实现

面向 Linux 路由软件的 C11 组件，实现 RFC 5925 TCP Authentication Option
(TCP-AO) 与 RFC 5926 的两个强制算法族：`KDF_HMAC_SHA1`/HMAC-SHA1-96 和
`KDF_AES_128_CMAC`/AES-128-CMAC-96。目标是在不重启 BGP/TCP 会话、不引起
路由震荡的前提下完成主密钥安装、连接级流量密钥派生、SendID/RecvID 选钥、
异步滚动换钥、序列号回绕和 TCP-MD5 老设备共存。

`make test` 中的 MAC/KDF 用例包含 IETF TCP-AO 测试向量（Scapy
`tcpao.uts` 中引用的 draft-touch-tcpm-ao-test-vectors 4.1.1、4.1.3、4.2.3、
5.1.1），覆盖 HMAC-SHA1、AES-128-CMAC 和排除其他 TCP 选项的模式。

## 功能对照

| 需求 | 实现 |
|---|---|
| 主密钥表 MKT | `src/ao_table.c`：线程安全表、通配选择符、SendID/RecvID 唯一性检查、安全清除 |
| 按连接派生流量密钥 | `src/ao_kdf.c`、`src/ao_aes_cmac.c`、`src/ao_conn.c`：RFC 5926 HMAC-SHA1/AES-CMAC KDF、IPv4/IPv6 context、双向及 SYN/established 四类密钥缓存 |
| 按发送/接收标识选钥 | `ao_table_find_send_id()` / `ao_table_find_recv_id()`，以及 per-connection key ring |
| 不断会话滚动换钥 | `src/ao_rotation.c` + RFC 5925 Current_key/RNext_key 状态迁移，允许乱序导致的 temporary backup |
| 两端换钥时间不同步 | 新、旧 MKT 同时保留；通过 TCP-AO `KeyID` 与 `RNextKeyID` 协商，而不是依赖时钟 |
| 扩展序列号 | `src/ao_sne.c` 精确实现 RFC 5925 §6.2；SNE 以大端 32 位参与 MAC，测试覆盖回绕和乱序窗口 |
| 标准 MAC/选项 | `src/ao_codec.c`、`src/ao_conn.c`：Kind=29、HMAC-SHA1-96 与 AES-128-CMAC-96、伪首部、checksum/MAC 清零、`EXCLUDE_OPT` |
| Linux 内核接入 | `src/pal/ao_linux.c`：`TCP_AO_ADD_KEY`(38)、`TCP_AO_DEL_KEY`(39)、`TCP_AO_INFO`(40)、`TCP_MD5SIG`/`TCP_MD5SIG_EXT` |
| MD5 老设备共存 | `ao_peer_policy_t` 与 `ao_linux_add_md5()`；监听口可分别配置 AO 和 MD5 对端选择符 |
| 不丢路由更新 | `src/bgp_journal.c`：完整 BGP 消息入队，短写/`EAGAIN` 保留偏移，换钥收敛并排空后才删旧钥 |

## 构建与测试

```sh
make
make test
```

也提供 CMake：

```sh
cmake -S . -B build-cmake
cmake --build build-cmake
ctest --test-dir build-cmake --output-on-failure
```

测试包括：

- SHA-1/HMAC-SHA1 标准向量；
- RFC 5926 context/KDF 固定值；
- IETF TCP-AO SHA-1 报文和 `EXCLUDE_OPT` 向量；
- SNE 回绕、回绕后乱序和 MAC 验证；
- SendID/RecvID 查找及冲突；
- 双端不同步换钥、旧 KeyID 乱序/back-up；
- 10 条更新在换钥和 back-up 期间经 journal/AO 链路全部到达；
- journal 部分写、`EAGAIN` 重试和背压；
- MD5/AO 策略选择。

示例程序：

```sh
make all
./examples/bgp_ao_rollover
```

## 核心标识规则

每个 MKT 在本机视角有两个 ID：

- `send_id`：本端发送时写入 TCP-AO 选项的 `KeyID`，也是对端的 `RecvID`；
- `recv_id`：本端校验入向报文时匹配的 `KeyID`。

另外：

- 出向选项的 `KeyID = current_key.send_id`；
- 出向选项的 `RNextKeyID = rnext_key.recv_id`；
- 收到报文后，用选项 `KeyID` 匹配入向 MKT 的 `recv_id`；
- MAC 验证通过后，把收到的 `RNextKeyID` 与当前出向 MKT 的 `send_id` 比较；
  不同且能按该 ID 找到 MKT 时，内核/RFC 状态机把 `current_key` 切过去。

因此两端的 ID 通常是镜像关系。例如：

| 方向 | A 端 SendID/RecvID | B 端 SendID/RecvID |
|---|---:|---:|
| 旧钥 | `10 / 20` | `20 / 10` |
| 新钥 | `11 / 21` | `21 / 11` |

## 推荐滚动流程

1. **预置但不启用新钥**：两端都通过 `TCP_AO_ADD_KEY` 安装新 MKT，
   `set_current=0, set_rnext=0`。旧钥仍是 current/rnext。
2. **A 到了维护窗口**：调用
   `ao_linux_set_rnext(fd, new_a.recv_id)`，对应
   `TCP_AO_INFO.set_rnext=1`。A 后续报文仍可用旧 `KeyID`，但
   `RNextKeyID` 开始请求 B 的新 SendID。
3. **B 自动切换出向 current**：B 收到并验证旧 `KeyID` 后，发现
   `RNextKeyID` 等于新 MKT 的 SendID，于是内核将 B 的 `current_key`
   切到新钥。B 开始用新 `KeyID` 发包，但 B 的 `RNextKeyID` 可能仍旧，
   因为 B 的独立换钥时刻还没到。
4. **B 到窗口后执行第 2 步镜像操作**：B 设置自己的 rnext 为新
   RecvID。A 收到后切换到新 current。
5. **重叠期保留两把钥**：不要删除旧 MKT。乱序报文可能在看到新
   `RNextKeyID` 后又因旧 `RNextKeyID` 把 current 临时切回旧钥，这是
   RFC 明确允许且用于避免丢包的 “backing up”。入向校验始终按报文
   `KeyID` 查找，不依赖 current。
6. **确认双向收敛和排空**：
   - `ao_linux_get_info()` 中 current/rnext 均为新 ID；
   - 新 RecvID 的 `pkt_good` 增长，说明对端确实已用新 KeyID；
   - BGP journal 为空；
   - 可用 `ao_linux_send_queue_bytes()`/`TCP_INFO` 观察发送队列，并保留
     一个大于网络乱序/MSL 的宽限期。
7. **删除旧钥**：调用普通 `ao_linux_del_mkt()` /
   `TCP_AO_DEL_KEY`。只有对端长期忽略 `RNextKeyID`、必须强制吊销时，才使用
   `ao_linux_force_del_mkt()`；该操作可能断会话，不属于正常滚动流程。

可运行的双端状态迁移见 `test_hitless_rotation_and_backup()`，带路由更新
journal 的端到端无丢失检查见
`test_no_update_loss_during_rotation()`。

## 连接级流量密钥

RFC 5926 context 为：

```text
IPv4: src(4) || dst(4) || src_port(2) || dst_port(2)
      || src_ISN(4) || dst_ISN(4)                 = 20 octets

IPv6: src(16) || dst(16) || ports(4) || ISNs(8)   = 44 octets
```

方向按“本报文发送方为 source”解释，所以出向用本机地址/ISN 作 source，入向
用对端地址/ISN 作 source。纯 SYN（SYN 置位且 ACK 未置位）的 destination
ISN 按 RFC 置零；其余报文使用已知 ISN 对。

KDF 输入为：

```text
i(1) || "TCP-AO" || Context || Output_Length_bits(2, big endian)
```

`KDF_HMAC_SHA1` 的主密钥直接作为 HMAC key，输出 160 bit 流量密钥，
MAC 截断前 96 bit。`KDF_AES_128_CMAC` 在主密钥不是 16 字节时先用全零 AES
密钥对主密钥做 CMAC extract，再用得到的 128 bit key 计算 counter-mode PRF，
输出 128 bit 流量密钥。Linux 适配器把主密钥和算法名交给内核，由内核在握手和
TCB 中完成实际派生；本仓库的可移植派生/MAC 实现可用于路由软件自检、用户态
协议栈或离线诊断，并已用公开测试向量验证。

## SNE 与序列号回绕

TCP 序列号只有 32 bit。TCP-AO 在 MAC 输入最前面增加 32 bit SNE，形成逻辑
64 bit 序列号。`ao_sne_next_rfc5925()` 保留 RFC 中的
`prev_seq`、`sne_flag` 和 `0x7fff` 回绕后窗口判断：

- 第一次从高序列号区间进入低区间时 `sne++` 并置 flag；
- flag 期间收到仍高于 `0x7fff` 的乱序报文时，使用 `sne - 1`；
- 序列号走到中段后清 flag；
- 下一次回绕继续递增。

生产 Linux 数据面由内核 `tcp_ao_compute_sne()` 结合 `snd_una`/`rcv_nxt`
完成等价判断；用户态若自行组包或做协议诊断，可直接使用本组件。

## 与 TCP-MD5 老设备共存

RFC 5925 和 Linux 实现都不支持把一条已经建立的 TCP-MD5 连接原地升级成
TCP-AO：TCP-MD5 没有算法协商/KeyID/RNext 机制，而且 TCP-AO 流量密钥依赖
ISN。正确的平滑共存方式是：

1. 监听 socket 同时安装：
   - 支持 AO 的对等体/网段：`ao_linux_add_mkt()`；
   - 仅支持 RFC 2385 MD5 的老对等体：`ao_linux_add_md5()`。
2. Linux 不允许对**完全相同的 peer 选择符**同时添加 AO 和 MD5 key；应按
   对等体 IP、前缀或模板区分。
3. 老设备的现有 BGP 会话继续使用 MD5，直到计划内重建或对端升级；新会话优先
   使用 AO。
4. 对外连场景，在配置/能力发现中明确 `AO_ONLY`、`MD5_ONLY`、`AUTO` 或
   `DUAL_LISTENER`，不要在 AO 握手失败后静默把同一条连接降级为 MD5，除非
   安全策略明确允许。

## 如何保证换钥时不丢路由更新

TCP 本身保证可靠有序，但短写、非阻塞 `EAGAIN` 和用户态换钥时序仍可能让路由
进程误判发送失败。集成时应把每条完整 BGP message 交给
`bgp_update_writer_t`：

```c
bgp_writer_enqueue(&w, bgp_msg, bgp_msg_len, NULL);
rc = bgp_writer_flush(&w, maybe_nonblocking_send, &io);
if (rc == AO_EAGAIN) {
    /* 等待 EPOLLOUT，然后用同一个 writer 继续 flush。 */
}
```

writer 会保留当前消息和已写字节偏移，不会从中间重发，也不会越过未完成消息
发送下一条。换钥控制面与 BGP 写线程可以并行，但应串行化同一个 `ao_conn_t`
或直接让 Linux 内核维护 per-socket key 状态。

不要在观察到第一次新 `KeyID` 时立刻删除旧钥。至少满足：

- 本端 current/rnext 已切新；
- 对端新 KeyID 和 RNext 请求均已观察到；
- journal 中所有消息已被 `write()`/`send()` 接受；
- 内核发送队列和 TCP 重传队列已排空或经过宽限期；
- 旧 RecvID 不再出现需要用旧钥验证的乱序报文。

这样换钥只是修改认证状态，不关闭 fd、不清 BGP Adj-RIB-Out，也不触发
session reset，因此不会产生路由撤销/重宣告震荡。

## 集成到 FRR/BIRD 等路由软件

典型接线点：

1. BGP TCP socket 创建后，在 `connect()`/`listen()` 前初始化策略；
2. 用 `ao_table_add()` 保存配置中的 MKT；
3. 对监听 socket 逐个调用 `ao_linux_add_mkt()`，对老 peer 调用
   `ao_linux_add_md5()`；
4. `accept()` 返回后检查 `TCP_AO_INFO`/`TCP_AO_GET_KEYS`，处理文档中说明的
   listener 与 accept-queue key race，必要时把 key 补装到已接受 fd；
5. 配置 reload 产生新 MKT 时先 add，再 `TCP_AO_INFO` 设置 rnext；
6. BGP I/O 线程使用 journal/partial-write helper；
7. 监控 `pkt_bad`、`pkt_key_not_found`、`pkt_ao_required`，换钥失败时告警并
   将 rnext 回退旧钥，而不是强制删旧钥。

## 目录

```text
include/tcp_ao.h          可移植核心 API
include/tcp_ao_linux.h    Linux setsockopt 适配 API
src/sha1.c                SHA-1/HMAC-SHA1
src/ao_aes_cmac.c         AES-128、AES-CMAC 与 AES KDF
src/ao_kdf.c              RFC 5926 KDF/context
src/ao_sne.c              RFC 5925 SNE
src/ao_codec.c            TCP-AO option codec
src/ao_conn.c             连接 key ring、签名、验证、RNext 切钥
src/ao_table.c            主密钥表
src/ao_rotation.c         滚动换钥状态机
src/bgp_journal.c         不丢更新的写队列
src/ao_policy.c           AO/MD5 共存策略
src/pal/ao_linux.c        Linux TCP_AO/TCP_MD5 setsockopt
tests/test_tcp_ao.c       单元、标准向量和换钥仿真
examples/                 最小可运行示例
```

## 参考

- [RFC 5925: The TCP Authentication Option](https://www.rfc-editor.org/rfc/rfc5925)
- [RFC 5926: Cryptographic Algorithms for TCP-AO](https://www.rfc-editor.org/rfc/rfc5926)
- [Linux TCP Authentication Option implementation notes](https://www.kernel.org/doc/html/latest/networking/tcp_ao.html)
- [Linux `uapi/linux/tcp.h` TCP_AO structures](https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h)
