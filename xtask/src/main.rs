//! `cargo xtask <task>`: thin wrapper around [`xtask::run`].

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match xtask::run(&args, &xtask::Ctx::from_env()) {
        Ok(out) => print!("{out}"),
        Err(e) => {
            eprintln!("xtask: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn library_is_linked() {
        assert!(xtask::USAGE.contains("dev-check"));
    }
}
