// Logo Escale (« E » en trois voies) rasterisé par SDF, sans dépendance.
// Partagé entre build.rs (génération de l'.ico) et l'app (icône de fenêtre + écran d'accueil).
// Même dessin que assets/logo.svg ; le marquage au sol n'apparaît qu'à partir de 192 px (illisible en dessous).

/// Contour du « E » (repère 512 x 512), arrondi par un décalage de `ROUND`.
const E_POLY: [(f32, f32); 12] = [
    (130.0, 106.0),
    (388.0, 106.0),
    (360.0, 158.0),
    (206.0, 158.0),
    (206.0, 230.0),
    (332.0, 230.0),
    (304.0, 282.0),
    (206.0, 282.0),
    (206.0, 354.0),
    (388.0, 354.0),
    (360.0, 406.0),
    (130.0, 406.0),
];
const ROUND: f32 = 10.0;

/// Traits du marquage au sol : (x, y, largeur) ; hauteur fixe de 8, bouts arrondis.
const MARKS: [(f32, f32, f32); 5] = [(236.0, 127.0, 48.0), (298.0, 127.0, 30.0), (236.0, 251.0, 34.0), (236.0, 375.0, 48.0), (298.0, 375.0, 30.0)];

fn poly_dist(px: f32, py: f32, pts: &[(f32, f32)]) -> f32 {
    let mut d = (px - pts[0].0).powi(2) + (py - pts[0].1).powi(2);
    let mut s = 1.0f32;
    let mut j = pts.len() - 1;
    for i in 0..pts.len() {
        let (ex, ey) = (pts[j].0 - pts[i].0, pts[j].1 - pts[i].1);
        let (wx, wy) = (px - pts[i].0, py - pts[i].1);
        let h = ((wx * ex + wy * ey) / (ex * ex + ey * ey)).clamp(0.0, 1.0);
        let (bx, by) = (wx - ex * h, wy - ey * h);
        d = d.min(bx * bx + by * by);
        let c = [py >= pts[i].1, py < pts[j].1, ex * wy > ey * wx];
        if c.iter().all(|&v| v) || c.iter().all(|&v| !v) {
            s = -s;
        }
        j = i;
    }
    s * d.sqrt()
}

fn mark_dist(px: f32, py: f32, (x, y, w): (f32, f32, f32)) -> f32 {
    let (hw, hh) = (w / 2.0, 4.0);
    let qx = (px - (x + hw)).abs() - (hw - hh);
    let qy = (py - (y + hh)).abs();
    let (ox, oy) = (qx.max(0.0), (qy - 0.0).max(0.0));
    (ox * ox + oy * oy).sqrt() + qx.max(qy - hh).min(0.0) - hh
}

fn lerp(a: [f32; 3], b: [f32; 3], t: f32) -> [f32; 3] {
    [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t]
}

/// Rend le logo en RGBA (non prémultiplié, fond transparent), `size` x `size`.
pub fn render(size: u32) -> Vec<u8> {
    let s = size as f32;
    let u = 512.0 / s; // un pixel, en unités du repère 512
    let marks = size >= 192;
    let teal = [0.176, 0.831, 0.749]; // #2DD4BF
    let sky = [0.220, 0.741, 0.973]; // #38BDF8
    // dégradé de (120, 96) à (400, 416)
    let (gx, gy) = (280.0f32, 320.0f32);
    let g2 = gx * gx + gy * gy;

    let mut out = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            // super-échantillonnage 4x
            let (mut acc, mut cov) = ([0.0f32; 3], 0.0f32);
            for sy in 0..2 {
                for sx in 0..2 {
                    let px = (x as f32 + 0.25 + 0.5 * sx as f32) * u;
                    let py = (y as f32 + 0.25 + 0.5 * sy as f32) * u;
                    let mut a = (0.5 - (poly_dist(px, py, &E_POLY) - ROUND) / u).clamp(0.0, 1.0);
                    if marks {
                        for m in MARKS {
                            a *= (0.5 + mark_dist(px, py, m) / u).clamp(0.0, 1.0);
                        }
                    }
                    let t = (((px - 120.0) * gx + (py - 96.0) * gy) / g2).clamp(0.0, 1.0);
                    let c = lerp(teal, sky, t);
                    for i in 0..3 {
                        acc[i] += c[i] * a * 0.25;
                    }
                    cov += a * 0.25;
                }
            }
            let un = |v: f32| if cov > 0.0 { (v / cov).clamp(0.0, 1.0) } else { 0.0 };
            let to8 = |v: f32| (v * 255.0).round() as u8;
            out.extend_from_slice(&[to8(un(acc[0])), to8(un(acc[1])), to8(un(acc[2])), to8(cov.clamp(0.0, 1.0))]);
        }
    }
    out
}
