/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2013 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <cstring>

#include <rex/kernel/xam/module.h>
#include <rex/platform.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xsocket.h>
// #include <rex/system/xnet.h>

#include <rex/cvar.h>
#include <rex/logging.h>
#include <rex/memory/utils.h>
#include <rex/net/socket.h>

// Xbox titles bind fixed low ports (e.g. 1000 for system link). Unprivileged
// processes cannot bind ports < 1024 on POSIX hosts, so such ports are shifted by
// this offset on the host and shifted back for the guest. Every instance that
// should talk to each other must use the same offset.
#if REX_PLATFORM_WIN32
static constexpr uint32_t kDefaultPrivilegedPortOffset = 0;
#else
static constexpr uint32_t kDefaultPrivilegedPortOffset = 10000;
#endif
REXCVAR_DEFINE_UINT32(net_privileged_port_offset, kDefaultPrivilegedPortOffset, "Network",
                      "Host port offset applied to guest ports below 1024 (0 disables)")
    .range(0, 64000);

// Standard socket types used by Xbox API emulation
#if REX_PLATFORM_WIN32
#include <WinSock2.h>

#include <WS2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#endif

namespace rex::system {

namespace {
// Guest port -> host port (both in host byte order).
uint16_t HostPort(uint16_t guest_port) {
  const uint32_t offset = REXCVAR_GET(net_privileged_port_offset);
  if (offset && guest_port > 0 && guest_port < 1024) {
    return static_cast<uint16_t>(guest_port + offset);
  }
  return guest_port;
}

// Host port -> guest port (both in host byte order); inverse of HostPort.
uint16_t GuestPort(uint16_t host_port) {
  const uint32_t offset = REXCVAR_GET(net_privileged_port_offset);
  if (offset && host_port > offset && host_port - offset < 1024) {
    return static_cast<uint16_t>(host_port - offset);
  }
  return host_port;
}
}  // namespace

XSocket::XSocket(KernelState* kernel_state) : XObject(kernel_state, kObjectType) {}

XSocket::XSocket(KernelState* kernel_state, uint64_t native_handle)
    : XObject(kernel_state, kObjectType), native_handle_(native_handle) {}

XSocket::~XSocket() {
  Close();
}

X_STATUS XSocket::Initialize(AddressFamily af, Type type, Protocol proto) {
  af_ = af;
  type_ = type;
  proto_ = proto;

  if (proto == Protocol::X_IPPROTO_VDP) {
    // VDP is a layer on top of UDP.
    proto = Protocol::X_IPPROTO_UDP;
  }

  native_handle_ = socket(af, type, proto);
  if (native_handle_ == -1) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Close() {
  int ret = rex::net::socket_close(native_handle_);
  if (ret != 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::SetOption(uint32_t level, uint32_t optname, void* optval_ptr, uint32_t optlen) {
  if (level == 0xFFFF && (optname == 0x5801 || optname == 0x5802)) {
    // Disable socket encryption
    secure_ = false;
    return X_STATUS_SUCCESS;
  }

  // Guest passes Winsock levels/option names with big-endian values. Translate
  // integer options to host constants and byte order (POSIX SOL_SOCKET is 1 and
  // SO_BROADCAST is 6, not 0xFFFF/0x20).
  constexpr uint32_t kXSolSocket = 0xFFFF;
  constexpr uint32_t kXIpprotoTcp = 6;
  int host_level = -1;
  int host_optname = -1;
  if (level == kXSolSocket) {
    host_level = SOL_SOCKET;
    switch (optname) {
      case 0x0004:
        host_optname = SO_REUSEADDR;
        break;
      case 0x0008:
        host_optname = SO_KEEPALIVE;
        break;
      case 0x0020:
        host_optname = SO_BROADCAST;
        break;
      case 0x1001:
        host_optname = SO_SNDBUF;
        break;
      case 0x1002:
        host_optname = SO_RCVBUF;
        break;
      default:
        break;
    }
  } else if (level == kXIpprotoTcp && optname == 0x0001) {
    host_level = IPPROTO_TCP;
    host_optname = TCP_NODELAY;
  }
  if (host_optname < 0 || !optval_ptr || optlen < sizeof(uint32_t)) {
    REXSYS_WARN("XSocket::SetOption: unsupported level {:X} option {:X} (len {})", level, optname,
                optlen);
    return X_STATUS_NOT_IMPLEMENTED;
  }
  const int host_value = static_cast<int>(rex::memory::load_and_swap<uint32_t>(optval_ptr));
  int ret = setsockopt(native_handle_, host_level, host_optname,
                       reinterpret_cast<const char*>(&host_value), sizeof(host_value));
  if (ret < 0) {
    // TODO: WSAGetLastError()
    return X_STATUS_UNSUCCESSFUL;
  }

  // SO_BROADCAST
  if (level == 0xFFFF && optname == 0x0020) {
    broadcast_socket_ = true;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::IOControl(uint32_t cmd, uint8_t* arg_ptr) {
  // Guest uses Winsock command codes with a big-endian u_long argument. Translate
  // to the host's codes/byte order instead of handing them to ioctl verbatim
  // (POSIX FIONBIO is 0x5421, not 0x8004667E).
  constexpr uint32_t kXFionbio = 0x8004667E;
  constexpr uint32_t kXFionread = 0x4004667F;
  if (!arg_ptr) {
    return X_STATUS_INVALID_PARAMETER;
  }
  const uint32_t guest_value = rex::memory::load_and_swap<uint32_t>(arg_ptr);
#if REX_PLATFORM_WIN32
  u_long host_value = guest_value;
#else
  int host_value = static_cast<int>(guest_value);
#endif
  uint32_t host_cmd;
  switch (cmd) {
    case kXFionbio:
      host_cmd = FIONBIO;
      break;
    case kXFionread:
      host_cmd = FIONREAD;
      break;
    default:
      REXSYS_WARN("XSocket::IOControl: unsupported cmd {:08X}", cmd);
      return X_STATUS_NOT_IMPLEMENTED;
  }
  int ret =
      rex::net::socket_ioctl(native_handle_, host_cmd, reinterpret_cast<uint8_t*>(&host_value));
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }
  rex::memory::store_and_swap<uint32_t>(arg_ptr, static_cast<uint32_t>(host_value));
  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Connect(N_XSOCKADDR* name, int name_len) {
  N_XSOCKADDR host_name = *name;
  if (host_name.address_family == AF_INET) {
    // sockaddr_in layout: sa_data[0..1] is the port in network byte order.
    auto* port_bytes = reinterpret_cast<uint8_t*>(host_name.sa_data);
    const uint16_t port = HostPort(static_cast<uint16_t>(port_bytes[0] << 8 | port_bytes[1]));
    port_bytes[0] = static_cast<uint8_t>(port >> 8);
    port_bytes[1] = static_cast<uint8_t>(port);
  }
  int ret = connect(native_handle_, (sockaddr*)&host_name, name_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Bind(N_XSOCKADDR_IN* name, int name_len) {
  N_XSOCKADDR_IN host_name = *name;
  host_name.sin_port = HostPort(name->sin_port);
  int ret = bind(native_handle_, (sockaddr*)&host_name, name_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  bound_ = true;
  bound_port_ = name->sin_port;

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Listen(int backlog) {
  int ret = listen(native_handle_, backlog);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

object_ref<XSocket> XSocket::Accept(N_XSOCKADDR* name, int* name_len) {
  sockaddr n_sockaddr;
  socklen_t n_name_len = sizeof(sockaddr);
  uintptr_t ret = accept(native_handle_, &n_sockaddr, &n_name_len);
  if (ret == -1) {
    std::memset(name, 0, *name_len);
    *name_len = 0;
    return nullptr;
  }

  std::memcpy(name, &n_sockaddr, n_name_len);
  *name_len = n_name_len;

  // Create a kernel object to represent the new socket, and copy parameters
  // over.
  auto socket = object_ref<XSocket>(new XSocket(kernel_state_, ret));
  socket->af_ = af_;
  socket->type_ = type_;
  socket->proto_ = proto_;

  return socket;
}

int XSocket::Shutdown(int how) {
  return shutdown(native_handle_, how);
}

int XSocket::Recv(uint8_t* buf, uint32_t buf_len, uint32_t flags) {
  return recv(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags);
}

int XSocket::RecvFrom(uint8_t* buf, uint32_t buf_len, uint32_t flags, N_XSOCKADDR_IN* from,
                      uint32_t* from_len) {
  // Pop from secure packets first
  // TODO(DrChat): Enable when I commit XNet
  /*
  {
    std::lock_guard<std::mutex> lock(incoming_packet_mutex_);
    if (incoming_packets_.size()) {
      packet* pkt = (packet*)incoming_packets_.front();
      int data_len = pkt->data_len;
      std::memcpy(buf, pkt->data, std::min((uint32_t)pkt->data_len, buf_len));

      from->sin_family = 2;
      from->sin_addr = pkt->src_ip;
      from->sin_port = pkt->src_port;

      incoming_packets_.pop();
      uint8_t* pkt_ui8 = (uint8_t*)pkt;
      delete[] pkt_ui8;

      return data_len;
    }
  }
  */

  sockaddr_in nfrom;
  socklen_t nfromlen = sizeof(sockaddr_in);
  int ret = recvfrom(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags,
                     (sockaddr*)&nfrom, &nfromlen);
  if (from) {
    from->sin_family = nfrom.sin_family;
    from->sin_addr = ntohl(nfrom.sin_addr.s_addr);  // BE <- BE
    from->sin_port = GuestPort(ntohs(nfrom.sin_port));
    std::memset(from->x_sin_zero, 0, sizeof(from->x_sin_zero));
  }

  if (from_len) {
    *from_len = nfromlen;
  }

  return ret;
}

int XSocket::Send(const uint8_t* buf, uint32_t buf_len, uint32_t flags) {
  return send(native_handle_, reinterpret_cast<const char*>(buf), buf_len, flags);
}

int XSocket::SendTo(uint8_t* buf, uint32_t buf_len, uint32_t flags, N_XSOCKADDR_IN* to,
                    uint32_t to_len) {
  // Send 2 copies of the packet: One to XNet (for network security) and an
  // unencrypted copy for other Xenia hosts.
  // TODO(DrChat): Enable when I commit XNet.
  /*
  auto xam = kernel_state()->GetKernelModule<xam::XamModule>("xam.xex");
  auto xnet = xam->xnet();
  if (xnet) {
    xnet->SendPacket(this, to, buf, buf_len);
  }
  */

  sockaddr_in nto;
  if (to) {
    nto.sin_addr.s_addr = to->sin_addr;
    nto.sin_family = to->sin_family;
    nto.sin_port = htons(HostPort(to->sin_port));
  }

  return sendto(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags,
                to ? (sockaddr*)&nto : nullptr, to_len);
}

bool XSocket::QueuePacket(uint32_t src_ip, uint16_t src_port, const uint8_t* buf, size_t len) {
  packet* pkt = reinterpret_cast<packet*>(new uint8_t[sizeof(packet) + len]);
  pkt->src_ip = src_ip;
  pkt->src_port = src_port;

  pkt->data_len = (uint16_t)len;
  std::memcpy(pkt->data, buf, len);

  std::lock_guard<std::mutex> lock(incoming_packet_mutex_);
  incoming_packets_.push((uint8_t*)pkt);

  // TODO: Limit on number of incoming packets?
  return true;
}

}  // namespace rex::system
