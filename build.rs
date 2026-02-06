// Build script for geode-client
// Generates Rust code from geode.proto using prost-build and tonic-build.

fn main() {
    // Get glibc paths from environment for Nix compatibility
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

    // Export LDFLAGS for libc++ if needed
    if let Ok(gcc_lib) = std::env::var("NIX_LDFLAGS") {
        println!("cargo:rustc-env=LDFLAGS={}", gcc_lib);
    }

    // Generate Rust types and gRPC service client from geode.proto using
    // tonic-build (which internally uses prost-build for message types).
    tonic_build::configure()
        .build_server(false) // Client library only needs the client stub
        .build_client(true)
        .out_dir("src/generated")
        .compile_protos(&["proto/geode.proto"], &["proto/"])
        .expect("Failed to compile geode.proto");
}
