use super::*;

fn parsed(path: &[u8], query: Option<&[u8]>) -> Result<Search, LowUrlError> {
    parse_url_low(path, query, false)
}

fn list(items: &[&[u8]]) -> Option<Vec<Vec<u8>>> {
    Some(items.iter().map(|i| i.to_vec()).collect())
}

/// Every part is optional: a bare path is a base search of nothing; the
/// base, the attributes, the scope and the filter are read in turn, the
/// base and the filter decoded.
#[test]
fn a_url_names_its_search_part_by_part() {
    assert_eq!(parsed(b"/", None), Ok(Search::default()));
    assert_eq!(
        parsed(b"/dc=x%2cdc=y", None),
        Ok(Search {
            dn: Some(b"dc=x,dc=y".to_vec()),
            ..Search::default()
        })
    );
    assert_eq!(
        parsed(b"/dc=x", Some(b"cn,s%6e?SUB?(cn=%2a)")),
        Ok(Search {
            dn: Some(b"dc=x".to_vec()),
            scope: Scope::Subtree,
            filter: Some(b"(cn=*)".to_vec()),
            attrs: list(&[b"cn", b"sn"]),
        })
    );
    // Empty parts are none; the scope is a base search's.
    assert_eq!(
        parsed(b"/", Some(b"??(o=1)")),
        Ok(Search {
            filter: Some(b"(o=1)".to_vec()),
            ..Search::default()
        })
    );
    assert_eq!(parsed(b"/", Some(b"")), Ok(Search::default()));
    for (word, scope) in [
        (&b"one"[..], Scope::OneLevel),
        (b"onetree", Scope::OneLevel),
        (b"Base", Scope::Base),
        (b"sub", Scope::Subtree),
        (b"subtree", Scope::Subtree),
    ] {
        let mut q = b"?".to_vec();
        q.extend_from_slice(word);
        assert_eq!(parsed(b"/", Some(&q)).map(|s| s.scope), Ok(scope));
    }
}

/// The attributes end at the first empty or overlong one, as C's loop
/// does; one of 1024 bytes is read.
#[test]
fn the_attributes_end_at_an_empty_or_overlong_one() {
    let attrs = |q: &[u8]| parsed(b"/", Some(q)).map(|s| s.attrs);
    assert_eq!(attrs(b"a,b"), Ok(list(&[b"a", b"b"])));
    assert_eq!(attrs(b"a,"), Ok(list(&[b"a"])));
    assert_eq!(attrs(b"a,,b"), Ok(list(&[b"a"])));
    assert_eq!(attrs(b",a"), Ok(list(&[])));
    let long = vec![b'a'; MAX_ATTRIBUTE];
    let mut q = long.clone();
    q.extend_from_slice(b",b");
    assert_eq!(attrs(&q), Ok(list(&[&long, b"b"])));
    let mut q = vec![b'a'; MAX_ATTRIBUTE + 1];
    q.extend_from_slice(b",b");
    assert_eq!(attrs(&q), Ok(list(&[])));
    let mut q = b"b,".to_vec();
    q.extend_from_slice(&[b'a'; MAX_ATTRIBUTE + 1]);
    assert_eq!(attrs(&q), Ok(list(&[b"b"])));
}

/// C refuses a path without its slash, a scope it does not know and an
/// empty last part as bad syntax; a zero byte in the base or an
/// attribute, or a control byte in the filter, as if memory ran out.
/// Extensions are read past and ignored.
#[test]
fn a_url_is_refused_as_c_refuses_it() {
    assert_eq!(parsed(b"", None), Err(LowUrlError::InvalidSyntax));
    assert_eq!(parsed(b"dc=x", None), Err(LowUrlError::InvalidSyntax));
    assert_eq!(
        parsed(b"/", Some(b"?nonsuch")),
        Err(LowUrlError::InvalidSyntax)
    );
    assert_eq!(
        parsed(b"/", Some(b"??(cn=a)?")),
        Err(LowUrlError::InvalidSyntax)
    );
    assert_eq!(
        parsed(b"/", Some(b"??(cn=a)?x-ext")).map(|s| s.filter),
        Ok(Some(b"(cn=a)".to_vec()))
    );
    assert_eq!(parsed(b"/dc=%00", None), Err(LowUrlError::NoMemory));
    assert_eq!(parsed(b"/", Some(b"a%00")), Err(LowUrlError::NoMemory));
    assert_eq!(
        parsed(b"/", Some(b"??(cn=%0a)")),
        Err(LowUrlError::NoMemory)
    );
    // A control byte is a filter's to refuse, not a base's.
    assert_eq!(
        parsed(b"/dc=%0a", None).map(|s| s.dn),
        Ok(Some(b"dc=\n".to_vec()))
    );
}

/// Where each part must be UTF-8, as in C's Unicode build, a base, an
/// attribute or a filter that decodes to something else is refused as if
/// memory ran out, where it is read, before what follows it; UTF-8 is
/// read as it is. Elsewhere any bytes are read.
#[test]
fn a_part_that_is_not_utf8_is_refused_where_it_must_be() {
    let utf8 = |path: &[u8], query: Option<&[u8]>| parse_url_low(path, query, true);
    assert_eq!(utf8(b"/dc=%e9", None), Err(LowUrlError::NoMemory));
    assert_eq!(
        utf8(b"/dc=%e9", Some(b"?nonsuch")),
        Err(LowUrlError::NoMemory)
    );
    assert_eq!(
        utf8(b"/", Some(b"cn,%e9?nonsuch")),
        Err(LowUrlError::NoMemory)
    );
    assert_eq!(utf8(b"/", Some(b"??(cn=%e9)")), Err(LowUrlError::NoMemory));
    assert_eq!(
        utf8(b"/", Some(b"?nonsuch?(cn=%e9)")),
        Err(LowUrlError::InvalidSyntax)
    );
    assert_eq!(
        utf8(b"/dc=caf%c3%a9", Some(b"na%c3%afve??(cn=%c3%a9)")),
        Ok(Search {
            dn: Some("dc=café".as_bytes().to_vec()),
            filter: Some("(cn=é)".as_bytes().to_vec()),
            attrs: list(&["naïve".as_bytes()]),
            ..Search::default()
        })
    );
    assert_eq!(
        parsed(b"/dc=%e9", Some(b"%e9??(cn=%e9)")),
        Ok(Search {
            dn: Some(b"dc=\xe9".to_vec()),
            filter: Some(b"(cn=\xe9)".to_vec()),
            attrs: list(&[b"\xe9"]),
            ..Search::default()
        })
    );
}
