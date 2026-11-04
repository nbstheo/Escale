// Génère assets/escale.ico à partir du logo SDF puis l'embarque dans l'exe Windows.

mod logo {
    include!("src/logo.rs");
}

use std::io::Write;

fn ico(sizes: &[u32]) -> Vec<u8> {
    let images: Vec<Vec<u8>> = sizes
        .iter()
        .map(|&s| {
            let rgba = logo::render(s);
            let mut dib = Vec::new();
            // BITMAPINFOHEADER (hauteur doublée : XOR + AND)
            dib.extend_from_slice(&40u32.to_le_bytes());
            dib.extend_from_slice(&(s as i32).to_le_bytes());
            dib.extend_from_slice(&((s * 2) as i32).to_le_bytes());
            dib.extend_from_slice(&1u16.to_le_bytes());
            dib.extend_from_slice(&32u16.to_le_bytes());
            dib.extend_from_slice(&[0u8; 24]);
            for y in (0..s).rev() {
                for x in 0..s {
                    let i = ((y * s + x) * 4) as usize;
                    dib.extend_from_slice(&[rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]]);
                }
            }
            let mask_row = (s.div_ceil(32) * 4) as usize;
            dib.extend(std::iter::repeat_n(0u8, mask_row * s as usize));
            dib
        })
        .collect();

    let mut out = Vec::new();
    out.extend_from_slice(&[0, 0, 1, 0]);
    out.extend_from_slice(&(sizes.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * sizes.len() as u32;
    for (s, img) in sizes.iter().zip(&images) {
        let b = if *s >= 256 { 0 } else { *s as u8 };
        out.extend_from_slice(&[b, b, 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&(img.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += img.len() as u32;
    }
    for img in images {
        out.extend_from_slice(&img);
    }
    out
}

fn main() {
    println!("cargo:rerun-if-changed=src/logo.rs");
    println!("cargo:rerun-if-changed=build.rs");

    let ico_path = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("escale.ico");
    std::fs::File::create(&ico_path)
        .and_then(|mut f| f.write_all(&ico(&[16, 24, 32, 48, 64, 128, 256])))
        .expect("écriture de l'icône");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon(ico_path.to_str().unwrap());
        res.set("ProductName", "Escale");
        res.set("FileDescription", "Escale - client SSH, RDP et VNC");
        if let Err(e) = res.compile() {
            println!("cargo:warning=icône non embarquée : {e}");
        }
    }
}
