#[macro_use]
extern crate anyhow;
extern crate clap;

use anyhow::Result;
use clap::{App, Arg};
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::TcpListener;
use tokio::stream::StreamExt;

#[tokio::main]
async fn main() {
    let matches = App::new("socks5_server")
        .version("0.1.0")
        .author("pzc")
        .about("A socks5 server")
        .arg(
            Arg::with_name("addr")
                .short("a")
                .long("address")
                .value_name("ADDR")
                .help("listen address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("PORT")
                .help("listen port")
                .takes_value(true),
        )
        .get_matches();

    let host = matches
        .value_of("addr")
        .unwrap_or("127.0.0.1")
        .split(".")
        .into_iter()
        .map(|v| v.parse::<u8>().expect("invalid addr"))
        .collect::<Vec<u8>>();
    let host: [u8; 4] = (&host[..]).try_into().expect("invalid addr");
    let port = matches
        .value_of("port")
        .unwrap_or("1080")
        .parse::<u16>()
        .expect("invalid port");

    let server = Socks5Server::new(host, port);
    if let Err(err) = server.listen().await {
        eprintln!("{:?}", err);
    }
}

struct Socks5Server {
    host: [u8; 4],
    port: u16,
}

impl Socks5Server {
    pub fn new(host: [u8; 4], port: u16) -> Self {
        Socks5Server { host, port }
    }

    async fn listen(&self) -> Result<()> {
        let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(self.host)), self.port);
        println!(
            "socks5 server listening at: {:?}:{}",
            listen_addr.ip(),
            listen_addr.port()
        );
        let mut listener = TcpListener::bind(listen_addr).await?;
        while let Some(stream) = listener.next().await {
            match stream {
                Ok(stream) => {
                    tokio::spawn(async move {
                        let result = socks5::handle_tcp_stream(stream).await;
                        if let Err(err) = result {
                            eprintln!("connection error: {:?}", err);
                        }
                    });
                }
                Err(err) => {
                    return Err(anyhow!(err));
                }
            }
        }
        Ok(())
    }
}

pub mod socks5 {
    use anyhow::Result;
    use bytes::{BufMut, BytesMut};
    use std::convert::TryInto;
    use std::net::SocketAddr::*;
    use std::net::{Ipv4Addr, Ipv6Addr, Shutdown};
    use tokio::io::{self, AsyncReadExt, AsyncWriteExt, ErrorKind::*};
    use tokio::net::TcpStream;

    const SUPPORT_IDENTIFY_METHOD: u8 = 0x00; // NO AUTHENTICATION REQUIRED
    const SUPPORT_REQUEST_CMD: u8 = 0x01; // CONNECT

    #[derive(Debug)]
    enum DSTAddrPort {
        Ipv4([u8; 4], u16),
        Ipv6([u8; 16], u16),
        DomainName(String, u16),
    }

    pub async fn handle_tcp_stream(mut stream: TcpStream) -> Result<()> {
        let methods = negotiate(&mut stream).await?;
        sub_negotiate(&mut stream, methods).await?;
        let dst_addr = accept_request(&mut stream).await?;
        reply_request(&mut stream, dst_addr).await?;
        Ok(())
    }

    // The client connects to the server, and sends a version
    // identifier/method selection message:
    //
    //                 +----+----------+----------+
    //                 |VER | NMETHODS | METHODS  |
    //                 +----+----------+----------+
    //                 | 1  |    1     | 1 to 255 |
    //                 +----+----------+----------+
    //
    // The VER field is set to X'05' for this version of the protocol.  The
    // NMETHODS field contains the number of method identifier octets that
    // appear in the METHODS field.
    async fn negotiate(stream: &mut TcpStream) -> Result<Vec<u8>> {
        let mut buffer = [0u8; 2];
        let n = stream.read_exact(&mut buffer).await?;
        assert_eq!(n, 2);
        if buffer[0] != 0x05 {
            return Err(anyhow!("INVALID PROTOCOL VERSION"));
        }
        let methods = buffer[1] as usize;
        let mut buffer = vec![0; methods];
        let n = stream.read_exact(&mut buffer).await?;
        // let mut buffer = Vec::with_capacity(methods);
        // let n = stream.read_buf(&mut buffer).await?;
        assert_eq!(n, methods);
        Ok(buffer)
    }

    // The server selects from one of the methods given in METHODS, and
    // sends a METHOD selection message:
    //
    //                       +----+--------+
    //                       |VER | METHOD |
    //                       +----+--------+
    //                       | 1  |   1    |
    //                       +----+--------+
    //
    // If the selected METHOD is X'FF', none of the methods listed by the
    // client are acceptable, and the client MUST close the connection.
    //
    // The values currently defined for METHOD are:
    //
    //        o  X'00' NO AUTHENTICATION REQUIRED
    //        o  X'01' GSSAPI
    //        o  X'02' USERNAME/PASSWORD
    //        o  X'03' to X'7F' IANA ASSIGNED
    //        o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
    //        o  X'FF' NO ACCEPTABLE METHODS
    async fn sub_negotiate(stream: &mut TcpStream, methods: Vec<u8>) -> Result<()> {
        if let None = methods
            .iter()
            .find(|method| **method == SUPPORT_IDENTIFY_METHOD)
        {
            stream.write_all(&[0x05, 0xFF]).await?;
            stream.flush().await?;
            return Err(anyhow!("NO ACCEPTABLE METHODS"));
        }
        stream.write_all(&[0x05, SUPPORT_IDENTIFY_METHOD]).await?;
        stream.flush().await?;

        Ok(())
    }

    // The SOCKS request is formed as follows:
    //
    //      +----+-----+-------+------+----------+----------+
    //      |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    //      +----+-----+-------+------+----------+----------+
    //      | 1  |  1  | X'00' |  1   | Variable |    2     |
    //      +----+-----+-------+------+----------+----------+
    //
    //   Where:
    //
    //        o  VER    protocol version: X'05'
    //        o  CMD
    //           o  CONNECT X'01'
    //           o  BIND X'02'
    //           o  UDP ASSOCIATE X'03'
    //        o  RSV    RESERVED
    //        o  ATYP   address type of following address
    //           o  IP V4 address: X'01'
    //           o  DOMAINNAME: X'03'
    //           o  IP V6 address: X'04'
    //        o  DST.ADDR       desired destination address
    //        o  DST.PORT desired destination port in network octet
    //           order
    async fn accept_request(stream: &mut TcpStream) -> Result<DSTAddrPort> {
        let mut buffer = [0u8; 4];
        let n = stream.read_exact(&mut buffer).await?;
        assert_eq!(n, 4);
        if buffer[0] != 0x05 {
            return Err(anyhow!("INVALID PROTOCOL VERSION"));
        }
        if buffer[1] != SUPPORT_REQUEST_CMD {
            // Command not supported
            write_err_reply(stream, 0x07).await?;
            stream.flush().await?;
            return Err(anyhow!("INVALID REQUEST CMD"));
        }
        if buffer[2] != 0x00 {
            return Err(anyhow!("INVALID RESERVED DATA"));
        }
        let dst_addr = match buffer[3] {
            // IPV4
            0x01 => {
                let mut buffer = [0u8; 4 + 2];
                let n = stream.read_exact(&mut buffer).await?;
                assert_eq!(n, 4 + 2);
                let addr: [u8; 4] = buffer[..4].try_into()?;
                let port: [u8; 2] = buffer[4..].try_into()?;
                DSTAddrPort::Ipv4(addr, u16::from_be_bytes(port))
            }
            // Domain name
            0x03 => {
                let mut buffer = [0u8; 1];
                let n = stream.read_exact(&mut buffer).await?;
                assert_eq!(n, 1);
                let domain_name_length = buffer[0] as usize;
                let mut buffer = vec![0; domain_name_length + 2];
                let n = stream.read_exact(&mut buffer).await?;
                // let mut buffer = Vec::with_capacity(domain_name_length + 2);
                // let n = stream.read_buf(&mut buffer).await?;
                assert_eq!(n, domain_name_length + 2);
                let domain_name = String::from_utf8(buffer[..domain_name_length].to_vec())?;
                let port: [u8; 2] = buffer[domain_name_length..].try_into()?;
                DSTAddrPort::DomainName(domain_name, u16::from_be_bytes(port))
            }
            // IPV6
            0x04 => {
                let mut buffer = [0u8; 16 + 2];
                let n = stream.read_exact(&mut buffer).await?;
                assert_eq!(n, 16 + 2);
                let addr: [u8; 16] = buffer[..16].try_into()?;
                let port: [u8; 2] = buffer[16..].try_into()?;
                DSTAddrPort::Ipv6(addr, u16::from_be_bytes(port))
            }
            _ => {
                write_err_reply(stream, 0x08).await?;
                stream.flush().await?;
                return Err(anyhow!("INVALID ADDRESS TYPE"));
            }
        };
        Ok(dst_addr)
    }

    // The server evaluates the request, and
    // returns a reply formed as follows:
    //      +----+-----+-------+------+----------+----------+
    //      |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    //      +----+-----+-------+------+----------+----------+
    //      | 1  |  1  | X'00' |  1   | Variable |    2     |
    //      +----+-----+-------+------+----------+----------+
    //   Where:
    //        o  VER    protocol version: X'05'
    //        o  REP    Reply field:
    //           o  X'00' succeeded
    //           o  X'01' general SOCKS server failure
    //           o  X'02' connection not allowed by ruleset
    //           o  X'03' Network unreachable
    //           o  X'04' Host unreachable
    //           o  X'05' Connection refused
    //           o  X'06' TTL expired
    //           o  X'07' Command not supported
    //           o  X'08' Address type not supported
    //           o  X'09' to X'FF' unassigned
    //        o  RSV    RESERVED
    //        o  ATYP   address type of following address
    //           o  IP V4 address: X'01'
    //           o  DOMAINNAME: X'03'
    //           o  IP V6 address: X'04'
    //        o  BND.ADDR       server bound address
    //        o  BND.PORT       server bound port in network octet order
    //
    // Fields marked RESERVED (RSV) must be set to X'00'.
    async fn reply_request(stream: &mut TcpStream, dst_addr: DSTAddrPort) -> Result<()> {
        let dst_stream = match &dst_addr {
            DSTAddrPort::Ipv6(addr, port) => {
                TcpStream::connect((Ipv6Addr::from(*addr), *port)).await
            }
            DSTAddrPort::Ipv4(addr, port) => {
                TcpStream::connect((Ipv4Addr::from(*addr), *port)).await
            }
            DSTAddrPort::DomainName(domain_name, port) => {
                TcpStream::connect(format!("{}:{}", domain_name, port)).await
            }
        };
        match dst_stream {
            Ok(mut dst_stream) => {
                let dst_addr = dst_stream.peer_addr()?;

                let mut buffer = BytesMut::with_capacity(10);
                assert!(buffer.is_empty());
                buffer.put_slice(&[0x05, 0x00, 0x00]);
                match dst_addr {
                    V4(ipv4_addr) => {
                        buffer.put_u8(0x01);
                        buffer.put_slice(&ipv4_addr.ip().octets());
                        buffer.put_u16(ipv4_addr.port());
                    }
                    V6(ipv6_addr) => {
                        buffer.put_u8(0x04);
                        buffer.put_slice(&ipv6_addr.ip().octets());
                        buffer.put_u16(ipv6_addr.port());
                    }
                }
                // let buffer_len = buffer.len();
                stream.write_all(&buffer).await?;
                stream.flush().await?;
                let (mut local_reader, mut local_writer) = stream.split();
                let (mut dst_reader, mut dst_writer) = dst_stream.split();
                let future_1 = io::copy(&mut local_reader, &mut dst_writer);
                let future_2 = io::copy(&mut dst_reader, &mut local_writer);
                let res = tokio::try_join!(future_1, future_2);
                dst_stream.shutdown(Shutdown::Both)?;
                stream.shutdown().await?;
                if let Err(e) = res {
                    return Err(e.into());
                }
            }
            Err(err) => {
                eprintln!("Dial dst {:?} error: {}", dst_addr, err);
                let err_code = match err.kind() {
                    NotFound | NotConnected => 0x03,
                    PermissionDenied => 0x02,
                    ConnectionRefused => 0x05,
                    ConnectionAborted | ConnectionReset => 0x04,
                    AddrNotAvailable => 0x08,
                    TimedOut => 0x06,
                    _ => 0x01,
                };
                write_err_reply(stream, err_code).await?;
                return Err(anyhow!(err));
            }
        }
        Ok(())
    }

    async fn write_err_reply(stream: &mut TcpStream, rsp: u8) -> Result<()> {
        let data = [0x05, rsp, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        stream.write_all(&data[..]).await?;
        stream.flush().await?;
        Ok(())
    }
}
