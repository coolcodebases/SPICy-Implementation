// registers one spicy party offline and stores its registration and secret
// usage: spicy-precompute --role sender --n-g 10660 --id device-1 --out-dir out --prefix 10 id1 id2 ...
// usage: spicy-precompute --role receiver --max-m 20 --max-n 1024 --out-dir out --prefix 10 --ids-file ids.txt
// both roles need the same n_g, given by --n-g or computed from --max-m and --max-n
// --level wic registers for spicy wic, the default is cic
// writes the public <prefix>_spicy_registration.bin and the secret <prefix>_spicy_secret.bin

use std::path::PathBuf;
use std::time::Instant;

use rand::RngCore;
use spicy_ffi::party::{fresh_rng, recommended_n_g, ReceiverParty, SenderParty};
use spicy_ffi::wic::{WicReceiverParty, WicSenderParty};

fn usage() -> ! {
    eprintln!(
        "usage: spicy-precompute [--level cic|wic] --role sender|receiver (--n-g N | [--max-m M] [--max-n N]) [--id ID] \
         [--out-dir DIR] [--prefix P] [--ids-file FILE] [ID ...]"
    );
    std::process::exit(2)
}

fn num(v: Option<String>) -> Option<usize> {
    v.and_then(|v| v.parse().ok()).or_else(|| usage())
}

fn main() {
    let mut role = None;
    let mut wic = false;
    let mut n_g: Option<usize> = None;
    let mut max_m: Option<usize> = None;
    let mut max_n: Option<usize> = None;
    let mut id: Option<Vec<u8>> = None;
    let mut out_dir = PathBuf::from(".");
    let mut prefix = String::from("identity");
    let mut ids: Vec<Vec<u8>> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--role" => role = args.next(),
            "--level" => match args.next().as_deref() {
                Some("cic") => wic = false,
                Some("wic") => wic = true,
                _ => usage(),
            },
            "--n-g" => n_g = num(args.next()),
            "--max-m" => max_m = num(args.next()),
            "--max-n" => max_n = num(args.next()),
            "--id" => id = Some(args.next().unwrap_or_else(|| usage()).into_bytes()),
            "--out-dir" => out_dir = args.next().map(PathBuf::from).unwrap_or_else(|| usage()),
            "--prefix" => prefix = args.next().unwrap_or_else(|| usage()),
            "--ids-file" => {
                let f = args.next().unwrap_or_else(|| usage());
                let text = std::fs::read_to_string(&f).expect("read ids file");
                ids.extend(text.lines().map(str::trim).filter(|l| !l.is_empty()).map(|l| l.as_bytes().to_vec()));
            }
            "-h" | "--help" => usage(),
            _ => ids.push(a.into_bytes()),
        }
    }
    if ids.is_empty() {
        usage()
    }
    let is_sender = match role.as_deref() {
        Some("sender") => true,
        Some("receiver") => false,
        _ => usage(),
    };
    let n_g = n_g.unwrap_or_else(|| {
        let (m, n) = if is_sender { (max_m.or(Some(ids.len())), max_n) } else { (max_m, max_n.or(Some(ids.len()))) };
        match (m, n) {
            (Some(m), Some(n)) => {
                if wic { spicy_ffi::wic::recommended_n_g(m, n) } else { recommended_n_g(m, n) }.unwrap_or_else(|| usage())
            }
            _ => usage(),
        }
    });
    let id = id.unwrap_or_else(|| {
        let mut b = [0u8; 16];
        fresh_rng().fill_bytes(&mut b);
        b.iter().map(|x| format!("{x:02x}")).collect::<String>().into_bytes()
    });
    std::fs::create_dir_all(&out_dir).expect("create out dir");
    let t = Instant::now();
    let (reg, secret) = if wic && is_sender {
        let p = WicSenderParty::register(&id, &ids, n_g, &mut fresh_rng()).unwrap_or_else(|e| panic!("{e}"));
        (p.registration().to_vec(), p.export_secret())
    } else if wic {
        let p = WicReceiverParty::register(&id, &ids, n_g, &mut fresh_rng()).unwrap_or_else(|e| panic!("{e}"));
        (p.registration().to_vec(), p.export_secret())
    } else if is_sender {
        let p = SenderParty::register(&id, &ids, n_g, &mut fresh_rng()).unwrap_or_else(|e| panic!("{e}"));
        (p.registration().to_vec(), p.export_secret())
    } else {
        let p = ReceiverParty::register(&id, &ids, n_g, &mut fresh_rng()).unwrap_or_else(|e| panic!("{e}"));
        (p.registration().to_vec(), p.export_secret())
    };
    let elapsed = t.elapsed();
    let reg_path = out_dir.join(format!("{prefix}_spicy_registration.bin"));
    let sec_path = out_dir.join(format!("{prefix}_spicy_secret.bin"));
    std::fs::write(&reg_path, &reg).expect("write registration");
    std::fs::write(&sec_path, &secret).expect("write secret");
    eprintln!(
        "{} {} items, id {}, n_g {}, registration {} B, secret {} B, {:.2?} → {}, {}",
        if wic { "WIC" } else { "CIC" },
        ids.len(),
        String::from_utf8_lossy(&id),
        n_g,
        reg.len(),
        secret.len(),
        elapsed,
        reg_path.display(),
        sec_path.display()
    );
}
