//! `SecretPath` and `Namespace`: the AAD binds a path's exact bytes, so
//! what parses must be canonical, exactly the input, and the only spelling
//! of that path; and the listing range must hold exactly the paths below.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ferritor_core::path::{MAX_LEN, Namespace, SecretPath};

/// The rule, restated from the module docs, independently of the parser.
fn canonical(s: &str) -> bool {
    (1..=MAX_LEN).contains(&s.len())
        && s.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

fn one(s: &str) -> Option<SecretPath> {
    let parsed = SecretPath::parse(s);
    assert_eq!(parsed.is_ok(), canonical(s), "{s:?}: {parsed:?}");
    let namespace = Namespace::parse(s);
    assert_eq!(
        namespace.is_ok(),
        canonical(s) && !s.contains('/'),
        "{s:?}: {namespace:?}"
    );
    let path = parsed.ok()?;
    // Never rewritten, and stable.
    assert_eq!(path.as_str(), s);
    assert_eq!(SecretPath::parse(path.as_str()).as_ref(), Ok(&path));
    // The namespace is the first segment, and a namespace itself.
    let namespace = path.namespace();
    assert_eq!(
        Namespace::parse(namespace.as_str()).as_ref(),
        Ok(&namespace)
    );
    assert!(s == namespace.as_str() || s.starts_with(&format!("{namespace}/")));
    assert_eq!(namespace.as_path().namespace(), namespace);
    Some(path)
}

fuzz_target!(|input: (&str, &str)| {
    let (a, b) = input;
    let (Some(child), Some(parent)) = (one(a), one(b)) else {
        return;
    };
    // The listing range holds exactly the paths below (`COLLATE "C"` is
    // byte order, as `str`'s).
    let (lo, hi) = parent.descendant_range();
    let in_range = child.as_str() >= lo.as_str() && child.as_str() < hi.as_str();
    assert_eq!(in_range, child.is_under(&parent), "{child} under {parent}");
    if child.is_under(&parent) {
        assert_eq!(child.namespace(), parent.namespace());
        assert!(!parent.is_under(&child));
        assert_ne!(child, parent);
    }
});
