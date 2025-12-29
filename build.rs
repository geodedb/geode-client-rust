// Build script for geode-client
// Configures BoringSSL build for Nix environment

fn main() {
    // Get glibc paths from environment
    let glibc_include = std::env::var("CFLAGS")
        .or_else(|_| std::env::var("CMAKE_C_FLAGS"))
        .unwrap_or_default();

    let glibc_cxx_include = std::env::var("CXXFLAGS")
        .or_else(|_| std::env::var("CMAKE_CXX_FLAGS"))
        .unwrap_or_default();

    // Pass flags to boring-sys build
    if !glibc_include.is_empty() {
        println!("cargo:rustc-env=BORING_BSSL_CFLAGS={}", glibc_include);
        println!("cargo:rustc-env=CMAKE_C_FLAGS={}", glibc_include);
    }

    if !glibc_cxx_include.is_empty() {
        println!("cargo:rustc-env=BORING_BSSL_CXXFLAGS={}", glibc_cxx_include);
        println!("cargo:rustc-env=CMAKE_CXX_FLAGS={}", glibc_cxx_include);
    }

    // Also try to export CXXSTDLIB environment variable for libc++ if needed
    if let Ok(gcc_lib) = std::env::var("NIX_LDFLAGS") {
        println!("cargo:rustc-env=LDFLAGS={}", gcc_lib);
    }
}
