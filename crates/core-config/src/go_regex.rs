//! Go `regexp` syntax that the `regex` crate spells differently.
//!
//! Only `\Q...\E` is translated. Go (`regexp/syntax`, Perl flags) reads
//! everything after `\Q` up to the first `\E`, or to the end of the pattern,
//! as literal text, backslashes included. Inside a character class `\Q` is an
//! invalid escape in both engines, so classes are copied unchanged.
//!
//! The two syntaxes still differ elsewhere; see `docs/rule-set-regex.md`.

use std::borrow::Cow;

/// `pattern` with each `\Q...\E` span replaced by escaped literals.
pub fn translate(pattern: &str) -> Cow<'_, str> {
    if !pattern.contains("\\Q") {
        return Cow::Borrowed(pattern);
    }
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut rest = pattern;
    while let Some(c) = rest.chars().next() {
        match c {
            '\\' => {
                let mut chars = rest.chars();
                chars.next();
                match chars.next() {
                    Some('Q') => {
                        let span = &rest[2..];
                        let (literal, after) = match span.find("\\E") {
                            Some(end) => (&span[..end], &span[end + 2..]),
                            None => (span, ""),
                        };
                        push_literal(&mut out, literal);
                        rest = after;
                    }
                    Some(next) => {
                        // an escape pair, copied as is
                        let len = 1 + next.len_utf8();
                        out.push_str(&rest[..len]);
                        rest = &rest[len..];
                    }
                    None => {
                        out.push('\\');
                        rest = "";
                    }
                }
            }
            '[' => {
                let len = class_len(rest);
                out.push_str(&rest[..len]);
                rest = &rest[len..];
            }
            _ => {
                out.push(c);
                rest = &rest[c.len_utf8()..];
            }
        }
    }
    Cow::Owned(out)
}

/// One literal per character: letters and digits as they are, everything
/// else as `\x{..}`, which no flag (`x`, `i`) reinterprets.
fn push_literal(out: &mut String, literal: &str) {
    for c in literal.chars() {
        if c.is_alphanumeric() || c == '_' {
            out.push(c);
        } else {
            out.push_str(&format!("\\x{{{:X}}}", c as u32));
        }
    }
}

/// Byte length of the class starting at `class[0] == '['`, Go's way: a `]`
/// right after `[` or `[^` is literal, `[:name:]` is one unit, `\` escapes
/// the next character. Unterminated: the rest of the pattern.
fn class_len(class: &str) -> usize {
    let bytes = class.as_bytes();
    let mut at = 1;
    if bytes.get(at) == Some(&b'^') {
        at += 1;
    }
    if bytes.get(at) == Some(&b']') {
        at += 1;
    }
    while at < bytes.len() {
        match bytes[at] {
            b']' => return at + 1,
            b'\\' => {
                at += 1;
                // skip the whole escaped character, which may be multi-byte
                if let Some(c) = class[at..].chars().next() {
                    at += c.len_utf8();
                }
            }
            b'[' if bytes.get(at + 1) == Some(&b':') => match class[at + 2..].find(":]") {
                Some(end) => at += 2 + end + 2,
                None => at += 1,
            },
            _ => at += 1,
        }
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::translate;

    #[test]
    fn quoted_spans_become_literals() {
        assert_eq!(translate("^a.b$"), "^a.b$");
        assert_eq!(translate(r"^\Qa.b\E$"), r"^a\x{2E}b$");
        // unterminated: to the end of the pattern
        assert_eq!(translate(r"^\Qa.b"), r"^a\x{2E}b");
        // backslashes inside the span are literal; the first \E ends it
        assert_eq!(translate(r"^\Qa\b\E"), r"^a\x{5C}b");
        assert_eq!(translate(r"^\Qa\\E"), r"^a\x{5C}");
        assert_eq!(translate(r"^a\Q\E*$"), r"^a*$");
        // an escaped backslash before Q is not a quote
        assert_eq!(translate(r"^\\Qa"), r"^\\Qa");
        assert_eq!(translate(r"^\\\Q.\E"), r"^\\\x{2E}");
        // inside a class \Q is left for the engine to reject
        assert_eq!(translate(r"^[\Q]"), r"^[\Q]");
        assert_eq!(translate(r"[]\Q]\Q.\E"), r"[]\Q]\x{2E}");
        assert_eq!(translate(r"[[:alpha:]\Q]\Q.\E"), r"[[:alpha:]\Q]\x{2E}");
        assert_eq!(translate(r"\Qé ő\E"), r"é\x{20}ő");
    }
}
