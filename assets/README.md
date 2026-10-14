# ORRESS assets

Brand assets for ORRESS (Okiedocus Rusty Reverse Engineering Software Suite), generated from the
master logo with high-quality (Lanczos) resampling. All PNGs are RGBA and preserve the logo's
transparent background.

| File | Size | Use |
| --- | --- | --- |
| `logo-full.png` | 1254×1254 | Master copy (full resolution). |
| `logo.png` | 512×512 | General-purpose logo. |
| `logo-256.png` | 256×256 | Smaller logo. |
| `splash.png` | 1024×1024 | Splash / about screen. |
| `icon.ico` | 16–256 (7 sizes) | Windows application icon. |
| `icons/icon-{16,32,48,64,128,256,512}.png` | as named | Per-size app icons (Linux `.desktop`, packaging, stores). |
| `favicon.ico` | 16/32/48 | Website favicon. |
| `favicon-16.png`, `favicon-32.png` | 16/32 | Standalone favicon PNGs. |

Regenerate: the generation script resizes the master PNG into every size above. To rebuild the set,
run a Lanczos resize from `logo-full.png` (or the original master) into these targets.
