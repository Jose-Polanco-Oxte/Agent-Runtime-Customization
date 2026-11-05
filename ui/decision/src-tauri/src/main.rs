fn main() {
    if let Err(error) = arc_decision_ui_host::run_from_stdio() {
        eprintln!("Arc embedded decision UI host failed: {error:#}");
        std::process::exit(1);
    }
}
