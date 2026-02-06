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

    // Proto code generation is opt-in via GENERATE_PROTO=1 environment variable.
    // The generated code is checked into src/generated/geode.rs and used directly
    // by default. This avoids requiring protoc in CI or for regular development.
    //
    // To regenerate after changing proto/geode.proto:
    //   GENERATE_PROTO=1 cargo build
    if std::env::var("GENERATE_PROTO").is_ok_and(|v| v == "1") {
        tonic_build::configure()
            .build_server(false) // Client library only needs the client stub
            .build_client(true)
            .out_dir("src/generated")
            .compile_protos(&["proto/geode.proto"], &["proto/"])
            .expect("Failed to compile geode.proto");

        // Run rustfmt on the generated file so it matches project formatting.
        let _ = std::process::Command::new("rustfmt")
            .arg("src/generated/geode.rs")
            .status();
    }
}
