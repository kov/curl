//! LDAP's messages as a server sends them, for the tests' fake servers.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

/// A BER element: `tag`, its length and `content`.
pub(crate) fn ber(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    if content.len() < 128 {
        v.push(content.len() as u8);
    } else {
        v.push(0x82);
        v.extend_from_slice(&(content.len() as u16).to_be_bytes());
    }
    v.extend_from_slice(content);
    v
}

/// An LDAP message of `id` holding `op`.
pub(crate) fn ldap_message(id: u8, op: &[u8]) -> Vec<u8> {
    let mut content = ber(0x02, &[id]);
    content.extend_from_slice(op);
    ber(0x30, &content)
}

/// A result operation of `tag`: `code`, an empty matched name and `info`.
pub(crate) fn result_op(tag: u8, code: u8, info: &[u8]) -> Vec<u8> {
    let mut content = ber(0x0a, &[code]);
    content.extend_from_slice(&ber(0x04, b""));
    content.extend_from_slice(&ber(0x04, info));
    ber(tag, &content)
}

/// An entry named `dn` with `attrs`, each its type and values.
pub(crate) fn entry_op(dn: &[u8], attrs: &[(&[u8], &[&[u8]])]) -> Vec<u8> {
    let mut list = Vec::new();
    for (name, values) in attrs {
        let mut set = Vec::new();
        for v in *values {
            set.extend_from_slice(&ber(0x04, v));
        }
        let mut a = ber(0x04, name);
        a.extend_from_slice(&ber(0x31, &set));
        list.extend_from_slice(&ber(0x30, &a));
    }
    let mut content = ber(0x04, dn);
    content.extend_from_slice(&ber(0x30, &list));
    ber(0x64, &content)
}
