use egui::Color32;

/// Color for an entropy value (0..=8): blue for low, green for code-like, yellow for
/// dense, red for compressed or encrypted.
pub fn entropy_color(entropy: f32) -> Color32 {
    const STOPS: [(f32, [u8; 3]); 5] = [
        (0.0, [20, 30, 70]),
        (3.0, [40, 90, 170]),
        (5.5, [60, 170, 90]),
        (7.0, [230, 200, 60]),
        (8.0, [220, 60, 50]),
    ];
    let e = entropy.clamp(0.0, 8.0);
    for pair in STOPS.windows(2) {
        let ((a, ca), (b, cb)) = (pair[0], pair[1]);
        if e <= b {
            let t = (e - a) / (b - a);
            let mix = |i: usize| {
                (f32::from(ca[i]) + (f32::from(cb[i]) - f32::from(ca[i])) * t).round() as u8
            };
            return Color32::from_rgb(mix(0), mix(1), mix(2));
        }
    }
    Color32::from_rgb(220, 60, 50)
}

/// A distinct, readable color per section index, for the section bands in the hex view.
pub fn section_color(index: usize) -> Color32 {
    const PALETTE: [Color32; 8] = [
        Color32::from_rgb(97, 175, 239),
        Color32::from_rgb(152, 195, 121),
        Color32::from_rgb(229, 192, 123),
        Color32::from_rgb(198, 120, 221),
        Color32::from_rgb(86, 182, 194),
        Color32::from_rgb(224, 108, 117),
        Color32::from_rgb(209, 154, 102),
        Color32::from_rgb(171, 178, 191),
    ];
    PALETTE[index % PALETTE.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_colors_cover_range() {
        assert_eq!(entropy_color(-1.0), Color32::from_rgb(20, 30, 70));
        assert_eq!(entropy_color(8.0), Color32::from_rgb(220, 60, 50));
        assert_eq!(entropy_color(99.0), Color32::from_rgb(220, 60, 50));
        assert_ne!(entropy_color(5.5), entropy_color(7.0));
    }
}
