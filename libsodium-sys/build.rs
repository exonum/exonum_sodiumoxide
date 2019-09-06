extern crate num_cpus;
extern crate pkg_config;

const VERSION: &'static str = "1.0.17";
const MIN_VERSION: &'static str = "1.0.12";

#[cfg(not(windows))]
fn main() {
    use std::env;

    let mut should_build = false;

    let force_build = match env::var("SODIUM_BUILD").ok() {
        None => false,
        Some(ref x) if x == "0" => false,
        Some(_) => true,
    };

    if force_build {
        should_build = true;
    } else {
        if let Ok(lib_dir) = env::var("SODIUM_LIB_DIR") {
            println!("cargo:rustc-link-search=native={}", lib_dir);
            let mode = match env::var_os("SODIUM_STATIC") {
                Some(_) => "static",
                None => "dylib",
            };
            println!("cargo:rustc-link-lib={0}=sodium", mode);
            println!(
                "cargo:warning=Using unknown libsodium version. This crate is tested against \
                 {} and may not be fully compatible with other versions.",
                VERSION
            );
        } else if let Ok(lib_details) = pkg_config::Config::new()
            .atleast_version(MIN_VERSION)
            .probe("libsodium")
        {
            println!(" === found libsodium: {:#?}", lib_details);
            if lib_details.version != VERSION {
                println!(
                    "cargo:warning=Using libsodium version {}. This crate is tested against {} \
                     and may not be fully compatible with {}.",
                    lib_details.version, VERSION, lib_details.version
                );
            }
        } else {
            should_build = true;
        }
    }

    if should_build {
        use flate2::read::GzDecoder;
        use std::fs::{self, File};
        use std::process::Command;
        use tar::Archive;

        // Download gz tarball
        let basename = "libsodium-".to_string() + VERSION;
        let gz_filename = basename.clone() + ".tar.gz";
        let url = "https://github.com/jedisct1/libsodium/releases/download/".to_string() + VERSION
            + "/" + &gz_filename;
        let mut install_dir = get_install_dir();
        let mut source_dir = env::var("OUT_DIR").unwrap() + "/source";
        // Avoid issues with paths containing spaces by falling back to using /tmp
        let target = env::var("TARGET").unwrap();
        if install_dir.contains(" ") {
            let fallback_path = "/tmp/".to_string() + &basename + "/" + &target;
            install_dir = fallback_path.clone() + "/installed";
            source_dir = fallback_path.clone() + "/source";
            println!(
                "cargo:warning=The path to the usual build directory contains spaces and hence \
                 can't be used to build libsodium.  Falling back to use {}.  If running `cargo \
                 clean`, ensure you also delete this fallback directory",
                fallback_path
            );
        }
        let gz_path = source_dir.clone() + "/" + &gz_filename;
        fs::create_dir_all(&install_dir).unwrap();
        fs::create_dir_all(&source_dir).unwrap();

        let mut curl_cmd = Command::new("curl");
        let curl_output = curl_cmd
            .arg(&url)
            .arg("-sSLvo")
            .arg(&gz_path)
            .output()
            .unwrap_or_else(|error| {
                panic!("Failed to run curl command: {}", error);
            });
        if !curl_output.status.success() {
            panic!(
                "\n{:?}\n{}\n{}\n",
                curl_cmd,
                String::from_utf8_lossy(&curl_output.stdout),
                String::from_utf8_lossy(&curl_output.stderr)
            );
        }

        // Unpack the tarball
        let gz_archive = File::open(&gz_path).unwrap();
        let gz_decoder = GzDecoder::new(gz_archive);
        let mut archive = Archive::new(gz_decoder);
        archive.unpack(&source_dir).unwrap();
        source_dir.push_str(&format!("/{}", basename));

        // Clean up
        let _ = fs::remove_file(gz_path);

        // Run `./configure`
        let target_parts: Vec<&str> = target.split("-").collect();
        let mut target_arch = target_parts[0];
        if target_arch == "aarch64" {
            target_arch = "arm64";
        }
        let target_sys = target_parts[2];

        let mut path = env::var("PATH").expect("Error retrieving $PATH");
        let build = cc::Build::new();
        let (cc, mut cflags) = if target.contains("i686") {
            (
                format!("{} -m32", build.get_compiler().path().display()),
                env::var("CFLAGS").unwrap_or(String::from(" -march=i686 -O3")),
            )
        } else {
            (
                format!("{}", build.get_compiler().path().display()),
                env::var("CFLAGS").unwrap_or(String::from(" -march=native -O3")),
            )
        };

        if target_sys == "ios" {
            let xcode_dir_output = Command::new("xcode-select").arg("-p").output()
                .expect("failed to execute xcode-select");
            let xcode_dir_stdout = String::from_utf8_lossy(&xcode_dir_output.stdout);
            let xcode_dir  = xcode_dir_stdout.trim();

            let platform = if target_arch == "arm64" { "iPhoneOS" } else { "iPhoneSimulator" };
            let base_dir = format!("{}/Platforms/{}.platform/Developer", xcode_dir, platform);
            let sdk = format!("{}/SDKs/{}.sdk", base_dir, platform);

            path = format!("{}/usr/bin:{}/usr/sbin:{}", base_dir, base_dir, path);
            cflags = env::var("CFLAGS").unwrap_or(format!("-arch {} -O3 -fembed-bitcode -isysroot {} -mios-version-min=6.0", target_arch, sdk));
        }

        let prefix_arg = format!("--prefix={}", install_dir);
        let host = env::var("HOST").unwrap();
        let host_arg = format!("--host={}", target);
        let cross_compiling = target != host;
        let help = if cross_compiling {
            "***********************************************************\n\
             Possible missing dependencies.\n\
             See https://github.com/maidsafe/rust_sodium#cross-compiling\n\
             ***********************************************************\n\n"
        } else {
            ""
        };

        // Disable PIE for Ubuntu < 15.04 (see https://github.com/jedisct1/libsodium/issues/292)
        let get_disable_pie_arg = || {
            const DISABLE_PIE: &str = "--disable-pie";

            let mut lsb_release_cmd = Command::new("lsb_release");
            let lsb_release_output = lsb_release_cmd.arg("-irs").output();
            let lsb_release_output = match lsb_release_output {
                Ok(output) => output,
                Err(error) => {
                    println!("Failed to run 'lsb_release -irs': {}", error);
                    // Treat "Failed to execute the command" as "any other distribution".
                    return DISABLE_PIE;
                }
            };
            if !lsb_release_output.status.success() {
                panic!(
                    "\n{:?}\n{}\n{}\n",
                    lsb_release_cmd,
                    String::from_utf8_lossy(&lsb_release_output.stdout),
                    String::from_utf8_lossy(&lsb_release_output.stderr)
                );
            }
            let stdout = String::from_utf8_lossy(&lsb_release_output.stdout);

            let mut lines = stdout.split(|c: char| c.is_whitespace());
            let distro = lines.next().expect("Missing distributive name");
            let version = lines.next().expect("Missing distributive version");

            let mut lines = version.split('.');
            let major: u32 = lines
                .next()
                .expect("Missing major version")
                .parse()
                .expect("Major version is not a number");

            match distro {
                "Ubuntu" if major < 15 => DISABLE_PIE,
                // Exclude 16.04 LTS - see https://jira.bf.local/browse/ECR-846
                "Ubuntu" if version == "16.04" => DISABLE_PIE,
                "Ubuntu" => "",
                // Any other distribution.
                _ => DISABLE_PIE,
            }
        };
        let disable_pie_arg = get_disable_pie_arg();

        let mut configure_cmd = Command::new("./configure");
        let configure_output = configure_cmd
            .current_dir(&source_dir)
            .env("PATH", &path)
            .env("CC", &cc)
            .env("CFLAGS", &cflags)
            .arg(&prefix_arg)
            .arg(&host_arg)
            .arg("--enable-shared=no")
            .arg(disable_pie_arg)
            .output()
            .unwrap_or_else(|error| {
                panic!("Failed to run './configure': {}\n{}", error, help);
            });
        if !configure_output.status.success() {
            panic!(
                "\n{:?}\nCFLAGS={}\nCC={}\n{}\n{}\n{}\n",
                configure_cmd,
                cflags,
                cc,
                String::from_utf8_lossy(&configure_output.stdout),
                String::from_utf8_lossy(&configure_output.stderr),
                help
            );
        }

        // Run `make clean`
        let mut clean_cmd = Command::new("make");
        let clean_output = clean_cmd
            .current_dir(&source_dir)
            .arg("clean")
            .output()
            .unwrap_or_else(|error| {
                panic!("Failed to run 'make clean': {}\n{}", error, help);
            });
        if !clean_output.status.success() {
            panic!(
                "\n{:?}\n{}\n{}\n{}\n{}\n",
                clean_cmd,
                String::from_utf8_lossy(&configure_output.stdout),
                String::from_utf8_lossy(&clean_output.stdout),
                String::from_utf8_lossy(&clean_output.stderr),
                help
            );
        }

        // Run `make check`, or `make all` if we're cross-compiling
        let j_arg = format!("-j{}", num_cpus::get());
        let make_arg = if cross_compiling { "all" } else { "check" };
        let mut make_cmd = Command::new("make");
        let make_output = make_cmd
            .current_dir(&source_dir)
            .env("V", "1")
            .arg(make_arg)
            .arg(&j_arg)
            .output()
            .unwrap_or_else(|error| {
                panic!("Failed to run 'make {}': {}\n{}", make_arg, error, help);
            });
        if !make_output.status.success() {
            panic!(
                "\n{:?}\n{}\n{}\n{}\n{}\n{}",
                make_cmd,
                String::from_utf8_lossy(&configure_output.stdout),
                String::from_utf8_lossy(&clean_output.stdout),
                String::from_utf8_lossy(&make_output.stdout),
                String::from_utf8_lossy(&make_output.stderr),
                help
            );
        }

        // Run `make install`
        let mut install_cmd = Command::new("make");
        let install_output = install_cmd
            .current_dir(&source_dir)
            .arg("install")
            .output()
            .unwrap_or_else(|error| {
                panic!("Failed to run 'make install': {}", error);
            });
        if !install_output.status.success() {
            panic!(
                "\n{:?}\n{}\n{}\n{}\n{}\n{}\n",
                install_cmd,
                String::from_utf8_lossy(&configure_output.stdout),
                String::from_utf8_lossy(&clean_output.stdout),
                String::from_utf8_lossy(&make_output.stdout),
                String::from_utf8_lossy(&install_output.stdout),
                String::from_utf8_lossy(&install_output.stderr)
            );
        }

        println!("cargo:rustc-link-lib=static=sodium");
        println!("cargo:rustc-link-search=native={}/lib", install_dir);
        println!("cargo:include={}/include", install_dir);
    }
}

#[cfg(all(not(windows), not(feature = "use-installed-libsodium")))]
extern crate cc;
#[cfg(all(not(target_env = "msvc"), not(feature = "use-installed-libsodium")))]
extern crate flate2;
#[cfg(all(target_env = "msvc", not(feature = "use-installed-libsodium")))]
extern crate libc;
#[cfg(all(not(target_env = "msvc"), not(feature = "use-installed-libsodium")))]
extern crate tar;
#[cfg(all(target_env = "msvc", not(feature = "use-installed-libsodium")))]
extern crate zip;

#[cfg(not(feature = "use-installed-libsodium"))]
fn get_install_dir() -> String {
    use std::env;
    env::var("OUT_DIR").unwrap() + "/installed"
}

#[cfg(all(windows, not(feature = "use-installed-libsodium")))]
fn check_powershell_version() {
    let mut check_ps_version_cmd = ::std::process::Command::new("powershell");
    let check_ps_version_output = check_ps_version_cmd
        .arg("-Command")
        .arg("{If ($PSVersionTable.PSVersion.Major -lt 4) { exit 1 }}")
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run powershell command: {}", error);
        });
    if !check_ps_version_output.status.success() {
        panic!(
            "\n{:?}\n{}\n{}\nYou must have Powershell v4.0 or greater installed.\n\n",
            check_ps_version_cmd,
            String::from_utf8_lossy(&check_ps_version_output.stdout),
            String::from_utf8_lossy(&check_ps_version_output.stderr)
        );
    }
}

#[cfg(all(windows, not(feature = "use-installed-libsodium")))]
fn download_compressed_file() -> String {
    use std::process::Command;

    let basename = "libsodium-".to_string() + VERSION;
    let zip_filename = if cfg!(target_env = "msvc") {
        basename.clone() + "-msvc.zip"
    } else {
        basename.clone() + "-mingw.tar.gz"
    };
    let url = "https://download.libsodium.org/libsodium/releases/".to_string() + &zip_filename;
    let zip_path = get_install_dir() + "/" + &zip_filename;
    let command = "([Net.ServicePointManager]::SecurityProtocol = 'Tls12') -and \
                   ((New-Object System.Net.WebClient).DownloadFile(\""
        .to_string() + &url + "\", \"" + &zip_path + "\"))";
    let mut download_cmd = Command::new("powershell");
    let download_output = download_cmd
        .arg("-Command")
        .arg(&command)
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run powershell download command: {}", error);
        });
    if !download_output.status.success() {
        panic!(
            "\n{:?}\n{}\n{}\n",
            download_cmd,
            String::from_utf8_lossy(&download_output.stdout),
            String::from_utf8_lossy(&download_output.stderr)
        );
    }
    zip_path
}

#[cfg(all(windows, target_env = "msvc", not(feature = "use-installed-libsodium")))]
fn main() {
    use libc::S_IFDIR;
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::path::Path;
    use zip::ZipArchive;

    check_powershell_version();

    // Download zip file
    let install_dir = get_install_dir();
    let lib_install_dir = Path::new(&install_dir).join("lib");
    fs::create_dir_all(&lib_install_dir).unwrap();
    let zip_path = download_compressed_file();

    // Unpack the zip file
    let zip_file = File::open(&zip_path).unwrap();
    let mut zip_archive = ZipArchive::new(zip_file).unwrap();

    // Extract just the appropriate version of libsodium.lib and headers to the install path.  For
    // now, only handle MSVC 2015.
    let arch_path = if cfg!(target_pointer_width = "32") {
        Path::new("Win32")
    } else if cfg!(target_pointer_width = "64") {
        Path::new("x64")
    } else {
        panic!("target_pointer_width not 32 or 64")
    };

    let unpacked_lib = arch_path.join("Release/v140/static/libsodium.lib");
    for i in 0..zip_archive.len() {
        let mut entry = zip_archive.by_index(i).unwrap();
        let entry_name = entry.name().to_string();
        let entry_path = Path::new(&entry_name);
        let opt_install_path = if entry_path.starts_with("include") {
            let is_dir = (entry.unix_mode().unwrap() & S_IFDIR as u32) != 0;
            if is_dir {
                let _ = fs::create_dir(&Path::new(&install_dir).join(entry_path));
                None
            } else {
                Some(Path::new(&install_dir).join(entry_path))
            }
        } else if entry_path == unpacked_lib {
            Some(lib_install_dir.join("libsodium.lib"))
        } else {
            None
        };
        if let Some(full_install_path) = opt_install_path {
            let mut buffer = Vec::with_capacity(entry.size() as usize);
            assert_eq!(entry.size(), entry.read_to_end(&mut buffer).unwrap() as u64);
            let mut file = File::create(&full_install_path).unwrap();
            file.write_all(&buffer).unwrap();
        }
    }

    // Clean up
    let _ = fs::remove_file(zip_path);

    println!("cargo:rustc-link-lib=static=libsodium");
    println!(
        "cargo:rustc-link-search=native={}",
        lib_install_dir.display()
    );
    println!("cargo:include={}/include", install_dir);
}

#[cfg(all(windows, not(target_env = "msvc"), not(feature = "use-installed-libsodium")))]
fn main() {
    use flate2::read::GzDecoder;
    use std::fs::{self, File};
    use std::path::Path;
    use tar::Archive;

    check_powershell_version();

    // Download gz tarball
    let install_dir = get_install_dir();
    let lib_install_dir = Path::new(&install_dir).join("lib");
    fs::create_dir_all(&lib_install_dir).unwrap();
    let gz_path = download_compressed_file();

    // Unpack the tarball
    let gz_archive = File::open(&gz_path).unwrap();
    let gz_decoder = GzDecoder::new(gz_archive);
    let mut archive = Archive::new(gz_decoder);

    // Extract just the appropriate version of libsodium.a and headers to the install path
    let arch_path = if cfg!(target_pointer_width = "32") {
        Path::new("libsodium-win32")
    } else if cfg!(target_pointer_width = "64") {
        Path::new("libsodium-win64")
    } else {
        panic!("target_pointer_width not 32 or 64")
    };

    let unpacked_include = arch_path.join("include");
    let unpacked_lib = arch_path.join("lib\\libsodium.a");
    let entries = archive.entries().unwrap();
    for entry_result in entries {
        let mut entry = entry_result.unwrap();
        let entry_path = entry.path().unwrap().to_path_buf();
        let full_install_path = if entry_path.starts_with(&unpacked_include) {
            let include_file = entry_path.strip_prefix(arch_path).unwrap();
            Path::new(&install_dir).join(include_file)
        } else if entry_path == unpacked_lib {
            lib_install_dir.join("libsodium.a")
        } else {
            continue;
        };
        entry.unpack(full_install_path).unwrap();
    }

    // Clean up
    let _ = fs::remove_file(gz_path);

    println!("cargo:rustc-link-lib=static=sodium");
    println!(
        "cargo:rustc-link-search=native={}",
        lib_install_dir.display()
    );
    println!("cargo:include={}/include", install_dir);
}
