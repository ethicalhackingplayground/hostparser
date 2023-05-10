use async_std::io;
use async_std::io::prelude::*;
use clap::{App, Arg};
use futures::{stream::FuturesUnordered, StreamExt};
use governor::{Quota, RateLimiter};
use std::error::Error;
use tldextract::{TldExtractor, TldOption};
use tokio::{runtime::Builder, task};

#[derive(Clone, Debug)]
pub struct Job {
    host: Option<String>,
}

#[derive(Clone, Debug)]
pub struct JobResult {
    pub data: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    // parse the cli arguments
    let matches = App::new("hostparser")
        .version("0.1.3")
        .author("Blake Jacobs <krypt0mux@gmail.com>")
        .about("A very fast hostparser")
        .arg(
            Arg::with_name("rate")
                .short('r')
                .long("rate")
                .takes_value(true)
                .default_value("1000")
                .display_order(2)
                .help("Maximum in-flight requests per second"),
        )
        .arg(
            Arg::with_name("concurrency")
                .short('c')
                .long("concurrency")
                .default_value("100")
                .takes_value(true)
                .display_order(3)
                .help("The amount of concurrent requests"),
        )
        .arg(
            Arg::with_name("workers")
                .short('w')
                .long("workers")
                .default_value("1")
                .takes_value(true)
                .display_order(5)
                .help("The amount of workers"),
        )
        .get_matches();

    let rate = match matches.value_of("rate").unwrap().parse::<u32>() {
        Ok(n) => n,
        Err(_) => {
            println!("{}", "could not parse rate, using default of 1000");
            1000
        }
    };

    let concurrency = match matches.value_of("concurrency").unwrap().parse::<u32>() {
        Ok(n) => n,
        Err(_) => {
            println!("{}", "could not parse concurrency, using default of 100");
            100
        }
    };

    let w: usize = match matches.value_of("workers").unwrap().parse::<usize>() {
        Ok(w) => w,
        Err(_) => {
            println!("{}", "could not parse workers, using default of 1");
            1
        }
    };

    // Set up a worker pool with the number of threads specified from the arguments
    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(w)
        .build()
        .unwrap();

    // job channels
    let (job_tx, job_rx) = spmc::channel::<Job>();

    rt.spawn(async move { send_url(job_tx, rate).await });

    // process the jobs
    let workers = FuturesUnordered::new();

    // process the jobs for scanning.
    for _ in 0..concurrency {
        let jrx = job_rx.clone();
        workers.push(task::spawn(async move {
            //  run the detector
            run_parser(jrx).await
        }));
    }
    let _: Vec<_> = workers.collect().await;
    rt.shutdown_background();

    Ok(())
}

async fn send_url(
    mut tx: spmc::Sender<Job>,
    rate: u32,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    //set rate limit
    let lim = RateLimiter::direct(Quota::per_second(std::num::NonZeroU32::new(rate).unwrap()));

    let stdin = io::BufReader::new(io::stdin());
    let mut lines = stdin.lines();

    // send the jobs
    while let Some(line) = lines.next().await {
        let host = line.unwrap();
        lim.until_ready().await;
        let msg = Job {
            host: Some(host.to_string().clone()),
        };
        if let Err(_) = tx.send(msg) {
            continue;
        }
    }
    Ok(())
}

pub async fn run_parser(rx: spmc::Receiver<Job>) {
    while let Ok(job) = rx.recv() {
        let job_host = job.host.unwrap();
        let ext: TldExtractor = TldOption::default().build();
        let extractor = match ext.extract(&job_host) {
            Ok(extractor) => extractor,
            Err(_) => continue,
        };

        let mut root_domain = String::from("");

        let domain = match extractor.domain {
            Some(domain) => domain,
            None => continue,
        };

        let suffix = match extractor.suffix {
            Some(suffix) => suffix,
            None => continue,
        };

        root_domain.push_str(&domain);
        root_domain.push_str(".");
        root_domain.push_str(&suffix);

        println!("{}", root_domain.to_string());
    }
}
