//! Thin wrapper around [`lumen_bench::run`].

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match lumen_bench::run(&args) {
        Ok(out) => print!("{out}"),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn library_is_linked() {
        assert!(lumen_bench::run(&[]).unwrap().starts_with("usage"));
    }
}
