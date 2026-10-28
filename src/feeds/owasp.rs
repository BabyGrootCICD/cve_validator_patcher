//! OWASP Top 10 (2025) classification. OWASP does not publish an advisory
//! feed, so its contribution is mapping each collected advisory's CWEs onto
//! the Top 10 categories, which the report groups by.
use crate::model::Advisory;

pub const SOURCE: &str = "OWASP Top 10 (CWE mapping)";

/// Representative CWE → OWASP Top 10:2025 mapping.
const MAP: &[(&str, &[u32])] = &[
    (
        "A01:2025 Broken Access Control",
        &[
            22, 23, 24, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601,
            639, 651, 668, 706, 862, 863, 913, 918, 922, 1275,
        ],
    ),
    (
        "A02:2025 Security Misconfiguration",
        &[2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174],
    ),
    ("A03:2025 Software Supply Chain Failures", &[447, 494, 506, 829, 830, 915, 1035, 1104, 1357, 1395]),
    (
        "A04:2025 Cryptographic Failures",
        &[
            261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759,
            760, 780, 818, 916,
        ],
    ),
    (
        "A05:2025 Injection",
        &[
            20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113, 116, 138, 184, 470, 471, 564, 610, 643,
            644, 652, 917, 1336,
        ],
    ),
    (
        "A06:2025 Insecure Design",
        &[
            73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579,
            598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173,
        ],
    ),
    (
        "A07:2025 Authentication Failures",
        &[255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216],
    ),
    ("A08:2025 Software or Data Integrity Failures", &[345, 353, 426, 502, 565, 784]),
    ("A09:2025 Security Logging and Alerting Failures", &[117, 223, 532, 778]),
    (
        "A10:2025 Mishandling of Exceptional Conditions",
        &[248, 252, 280, 390, 391, 394, 396, 397, 400, 404, 416, 476, 674, 703, 754, 755, 770, 787, 125, 190, 119, 120, 1325, 1333],
    ),
];

pub fn categories(cwe: &str) -> impl Iterator<Item = &'static str> + '_ {
    let n: Option<u32> = cwe.strip_prefix("CWE-").and_then(|s| s.parse().ok());
    MAP.iter().filter(move |(_, ids)| n.map(|n| ids.contains(&n)).unwrap_or(false)).map(|(c, _)| *c)
}

/// Tag advisories in place; returns how many received at least one category.
pub fn tag(advisories: &mut [Advisory]) -> usize {
    let mut n = 0;
    for a in advisories.iter_mut() {
        let cats: Vec<&str> = a.cwes.iter().flat_map(|c| categories(c)).collect();
        if !cats.is_empty() {
            n += 1;
        }
        a.owasp.extend(cats.into_iter().map(str::to_string));
    }
    n
}

#[cfg(test)]
mod tests {
    #[test]
    fn maps_common_cwes() {
        assert_eq!(super::categories("CWE-79").collect::<Vec<_>>(), vec!["A05:2025 Injection"]);
        assert!(super::categories("CWE-506").any(|c| c.starts_with("A03")));
        assert_eq!(super::categories("NVD-CWE-Other").count(), 0);
    }
}
