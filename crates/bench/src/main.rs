//! Thin wrapper around [`bench::run`].

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match bench::run(&args) {
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
        assert!(bench::run(&[]).unwrap().starts_with("usage"));
    }
}
