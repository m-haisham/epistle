//! Rebuilds embedded SQLx migrations when their sources change.

fn main() {
    println!("cargo:rerun-if-changed=../../migrations");
}
