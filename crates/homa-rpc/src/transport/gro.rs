//! UDP GRO（Generic Receive Offload）接收合并（Windows）。
//!
//! 发送侧 GSO 段经内核切分后，接收侧若启用 `UDP_RECV_MAX_COALESCED_SIZE`，
//! 内核把大小相同的连续分片合并回一个大缓冲——一次 `recvmsg` 拿到多个
//! Homa 包（`UDP_COALESCED_INFO` 控制消息给出每包大小 stride）。
//!
//! 收益（与 GSO 对称）：1MiB 消息接收端从 874 次 recv + 锁 降到 ~17 次
//! recvmsg + 锁，且合并缓冲内拆包是零拷贝切片，无需逐包用户态拷贝。
//!
//! `WSARecvMsg` 是延迟加载扩展函数，须经 `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)`
//! 解析一次后缓存。零依赖：手写 FFI，不引入 windows-sys。

#![cfg(windows)]

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::windows::io::AsRawSocket;

/// 接收缓冲：容纳 GSO 段合并缓冲（≤64KB）+ 裕量
pub const RECV_BUF_SIZE: usize = 1 << 17;

#[repr(C)]
struct WSABUF {
    len: u32,
    buf: *mut u8,
}

#[repr(C, align(8))]
struct WSACMSGHDR {
    cmsg_len: usize,
    cmsg_level: i32,
    cmsg_type: i32,
}

#[repr(C)]
struct WSAMSG {
    name: *mut u8,
    namelen: i32,
    lp_buffers: *mut WSABUF,
    dw_buffer_count: u32,
    control: WSABUF,
    dw_flags: u32,
}

type WsaRecvMsgFn = unsafe extern "system" fn(
    s: usize,
    lp_msg: *mut WSAMSG,
    lpdw_num_bytes_recvd: *mut u32,
    lp_overlapped: *mut std::ffi::c_void,
    lp_completion_routine: *mut std::ffi::c_void,
) -> i32;

const IPPROTO_UDP: i32 = 17;
/// ws2ipdef.h：UDP_RECV_MAX_COALESCED_SIZE = 3
const UDP_RECV_MAX_COALESCED_SIZE: i32 = 3;
/// control 消息类型：UDP_COALESCED_INFO = 3
const UDP_COALESCED_INFO: i32 = 3;
/// SIO_GET_EXTENSION_FUNCTION_POINTER = _WSAIORW(IOC_WS2, 6)
const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;
/// WSAID_WSARECVMSG = {0xf689d7c8,0x6f1f,0x436b,{0x8a,0x53,0xe5,0x4f,0xe3,0x51,0xc3,0x22}}
const GUID_WSARECVMSG: [u8; 16] = [
    0xc8, 0xd7, 0x89, 0xf6, 0x1f, 0x6f, 0x6b, 0x43, 0x8a, 0x53, 0xe5, 0x4f, 0xe3, 0x51, 0xc3, 0x22,
];

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
    fn WSAIoctl(
        s: usize,
        dw_io_control_code: u32,
        lpv_in_buffer: *mut u8,
        cb_in_buffer: u32,
        lpv_out_buffer: *mut u8,
        cb_out_buffer: u32,
        lpcb_bytes_returned: *mut u32,
        lp_overlapped: *mut std::ffi::c_void,
        lp_completion_routine: *mut std::ffi::c_void,
    ) -> i32;
}

/// 解析一次 WSARecvMsg 函数指针（延迟加载扩展函数，每个 Transport 解析一次即可）
fn resolve_recv_msg_fn(sock: &UdpSocket) -> io::Result<WsaRecvMsgFn> {
    let mut guid = GUID_WSARECVMSG;
    let mut ptr: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut bytes: u32 = 0;
    let rc = unsafe {
        WSAIoctl(
            sock.as_raw_socket() as usize,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            guid.as_mut_ptr(),
            16,
            &mut ptr as *mut *mut std::ffi::c_void as *mut u8,
            std::mem::size_of::<*mut std::ffi::c_void>() as u32,
            &mut bytes,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc != 0 || ptr.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { std::mem::transmute(ptr) })
}

/// 启用 GRO 的接收句柄
pub struct Gro {
    recv_fn: WsaRecvMsgFn,
}

impl Gro {
    /// 在 socket 上启用 GRO 并解析 WSARecvMsg
    pub fn new(sock: &UdpSocket) -> io::Result<Self> {
        // 合并上限取 u16::MAX（msquic 同款）；loopback 实测 64KB 段可完整合并
        let max_coalesce: u32 = u16::MAX as u32;
        let rc = unsafe {
            setsockopt(
                sock.as_raw_socket() as usize,
                IPPROTO_UDP,
                UDP_RECV_MAX_COALESCED_SIZE,
                &max_coalesce as *const u32 as *const u8,
                std::mem::size_of::<u32>() as i32,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let recv_fn = resolve_recv_msg_fn(sock)?;
        Ok(Self { recv_fn })
    }

    /// 收一批：返回 (接收字节数, stride=每数据报字节数, 源地址)。
    /// 无数据时返回 WouldBlock。stride 来自 UDP_COALESCED_INFO（未合并则 = len）。
    pub fn recv(
        &self,
        sock: &UdpSocket,
        data: &mut [u8],
        ctrl: &mut [u8],
    ) -> io::Result<(usize, usize, SocketAddr)> {
        let mut name = [0u8; 128];
        let mut wsa_data = WSABUF {
            len: data.len() as u32,
            buf: data.as_mut_ptr(),
        };
        let mut wsa_msg = WSAMSG {
            name: name.as_mut_ptr(),
            namelen: name.len() as i32,
            lp_buffers: &mut wsa_data,
            dw_buffer_count: 1,
            control: WSABUF {
                len: ctrl.len() as u32,
                buf: ctrl.as_mut_ptr(),
            },
            dw_flags: 0,
        };
        let mut n: u32 = 0;
        let rc = unsafe {
            (self.recv_fn)(
                sock.as_raw_socket() as usize,
                &mut wsa_msg,
                &mut n,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        // 解码 control：stride = UDP_COALESCED_INFO，缺省 = 整包长度
        let mut stride = n;
        let mut off = 0usize;
        while off + std::mem::size_of::<WSACMSGHDR>() <= ctrl.len() {
            let cmsg = unsafe { &*(ctrl.as_ptr().add(off) as *const WSACMSGHDR) };
            if cmsg.cmsg_len < std::mem::size_of::<WSACMSGHDR>() {
                break;
            }
            if cmsg.cmsg_level == IPPROTO_UDP && cmsg.cmsg_type == UDP_COALESCED_INFO {
                let dp = (cmsg as *const WSACMSGHDR as usize) + 16; // 对齐头后即数据
                stride = unsafe { *(dp as *const u32) } as usize;
            }
            off += (cmsg.cmsg_len + 7) & !7;
        }
        // 源地址：sockaddr_in（family=2）或 sockaddr_in6（family=23）
        let family = u16::from_le_bytes([name[0], name[1]]);
        let src = if family == 2 && name.len() >= 8 {
            let port = u16::from_be_bytes([name[2], name[3]]);
            let ip = Ipv4Addr::new(name[4], name[5], name[6], name[7]);
            SocketAddr::from((ip, port))
        } else if family == 23 && name.len() >= 28 {
            // sockaddr_in6：family(2) + port(2) + flowinfo(4) + addr(16) + scope_id(4)
            let port = u16::from_be_bytes([name[2], name[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&name[8..24]);
            let ip = std::net::Ipv6Addr::from(octets);
            SocketAddr::from((ip, port))
        } else {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        };
        Ok((n, stride, src))
    }
}
