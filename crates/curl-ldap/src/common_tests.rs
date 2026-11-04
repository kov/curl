use super::*;
use std::mem::{offset_of, size_of};

/// The values and layouts `sys.rs` declares are the headers', in
/// `csrc/layout.c`'s order: a value or field out of step reads or writes
/// the wrong bytes, which no other test would see.
#[test]
fn the_declarations_are_the_headers() {
    use sys::*;
    let n = |v: usize| i64::try_from(v).unwrap();
    let ours: [i64; LAYOUT_LEN] = [
        LDAP_SUCCESS.into(),
        LDAP_OPT_SUCCESS.into(),
        LDAP_OPT_API_INFO.into(),
        LDAP_OPT_REFERRALS.into(),
        LDAP_OPT_PROTOCOL_VERSION.into(),
        LDAP_OPT_SOCKBUF.into(),
        LDAP_API_INFO_VERSION.into(),
        LDAP_MSG_ONE.into(),
        LDAP_RES_BIND.into(),
        LDAP_RES_SEARCH_ENTRY.into(),
        LDAP_RES_SEARCH_REFERENCE.into(),
        LDAP_RES_SEARCH_RESULT.into(),
        LDAP_RES_EXTENDED.into(),
        LBER_SB_OPT_DATA_READY.into(),
        LBER_SB_OPT_SET_MAX_INCOMING.into(),
        LBER_SBIOD_LEVEL_TRANSPORT.into(),
        LDAP_URL_SUCCESS.into(),
        LDAP_URL_ERR_MEM.into(),
        n(size_of::<berval>()),
        n(offset_of!(berval, bv_len)),
        n(offset_of!(berval, bv_val)),
        n(size_of::<ber_len_t>()),
        n(size_of::<ber_slen_t>()),
        n(size_of::<ber_socket_t>()),
        n(size_of::<LDAPURLDesc>()),
        n(offset_of!(LDAPURLDesc, lud_next)),
        n(offset_of!(LDAPURLDesc, lud_scheme)),
        n(offset_of!(LDAPURLDesc, lud_host)),
        n(offset_of!(LDAPURLDesc, lud_port)),
        n(offset_of!(LDAPURLDesc, lud_dn)),
        n(offset_of!(LDAPURLDesc, lud_attrs)),
        n(offset_of!(LDAPURLDesc, lud_scope)),
        n(offset_of!(LDAPURLDesc, lud_filter)),
        n(offset_of!(LDAPURLDesc, lud_exts)),
        n(offset_of!(LDAPURLDesc, lud_crit_exts)),
        n(size_of::<LDAPAPIInfo>()),
        n(offset_of!(LDAPAPIInfo, ldapai_info_version)),
        n(offset_of!(LDAPAPIInfo, ldapai_api_version)),
        n(offset_of!(LDAPAPIInfo, ldapai_protocol_version)),
        n(offset_of!(LDAPAPIInfo, ldapai_extensions)),
        n(offset_of!(LDAPAPIInfo, ldapai_vendor_name)),
        n(offset_of!(LDAPAPIInfo, ldapai_vendor_version)),
        n(size_of::<Sockbuf_IO_Desc>()),
        n(offset_of!(Sockbuf_IO_Desc, sbiod_level)),
        n(offset_of!(Sockbuf_IO_Desc, sbiod_sb)),
        n(offset_of!(Sockbuf_IO_Desc, sbiod_io)),
        n(offset_of!(Sockbuf_IO_Desc, sbiod_pvt)),
        n(offset_of!(Sockbuf_IO_Desc, sbiod_next)),
        n(size_of::<Sockbuf_IO>()),
        n(offset_of!(Sockbuf_IO, sbi_setup)),
        n(offset_of!(Sockbuf_IO, sbi_remove)),
        n(offset_of!(Sockbuf_IO, sbi_ctrl)),
        n(offset_of!(Sockbuf_IO, sbi_read)),
        n(offset_of!(Sockbuf_IO, sbi_write)),
        n(offset_of!(Sockbuf_IO, sbi_close)),
        Code::PROTOCOL_ERROR.0.into(),
        Code::SIZELIMIT_EXCEEDED.0.into(),
        Code::SASL_BIND_IN_PROGRESS.0.into(),
        Code::INVALID_CREDENTIALS.0.into(),
        Code::INSUFFICIENT_ACCESS.0.into(),
        Code::NO_MEMORY.0.into(),
        Code::NO_RESULTS_RETURNED.0.into(),
        UrlError::BAD_URL.0.into(),
        LDAP_OPT_NETWORK_TIMEOUT.into(),
        LDAP_OPT_X_TLS.into(),
        LDAP_OPT_X_TLS_CACERTFILE.into(),
        LDAP_OPT_X_TLS_REQUIRE_CERT.into(),
        LDAP_OPT_X_TLS_NEVER.into(),
        LDAP_OPT_X_TLS_DEMAND.into(),
        LDAP_OPT_X_TLS_HARD.into(),
        n(size_of::<timeval>()),
        n(offset_of!(timeval, tv_usec)),
    ];
    // SAFETY: a table of `LAYOUT_LEN` numbers C defines, read only.
    let theirs = unsafe { curl_ldap_values };
    for (i, (o, t)) in ours.iter().zip(theirs.iter()).enumerate() {
        assert_eq!(o, t, "entry {i} of csrc/layout.c");
    }
}

/// A URL's search is the library's reading of it; a bad one is the
/// library's number for what is wrong.
#[test]
fn a_url_names_its_search() {
    let s = parse_url(b"ldap://h:389/dc=example,dc=com?cn,mail?sub?(cn=a*)").unwrap();
    assert_eq!(s.dn.as_deref(), Some(&b"dc=example,dc=com"[..]));
    assert_eq!(s.scope, Scope::Subtree);
    assert_eq!(s.filter.as_deref(), Some(&b"(cn=a*)"[..]));
    assert_eq!(s.attrs, Some(vec![b"cn".to_vec(), b"mail".to_vec()]));
    let base = parse_url(b"ldap://h/").unwrap();
    assert_eq!((base.attrs, base.scope), (None, Scope::Base));
    let scope = |url: &[u8]| parse_url(url).unwrap().scope;
    assert_eq!(scope(b"ldap://h/dc=x??one"), Scope::OneLevel);
    assert_eq!(scope(b"ldap://h/dc=x??children"), Scope::Subordinate);
    assert_eq!(parse_url(b"http://h/"), Err(UrlError(3)));
    assert_eq!(parse_url(b"ldap://h/?a?nonsuch"), Err(UrlError(8)));
    assert_eq!(parse_url(b"ldap://h/\0x"), Err(UrlError::BAD_URL));
}

/// The library's words for a code are its own.
#[test]
fn a_code_is_described_in_the_library_s_words() {
    assert_eq!(describe(Code::SUCCESS), b"Success");
    assert_eq!(describe(Code::INVALID_CREDENTIALS), b"Invalid credentials");
}

/// The vendor's number is split as C splits it.
#[test]
fn the_vendor_s_number_is_split_as_c_splits_it() {
    assert_eq!(vendor_version(20610), (2, 6, 10));
    assert_eq!(vendor_version(123_456), (12, 34, 56));
    assert_eq!(vendor_version(7), (0, 0, 7));
}

/// A string for the library and a list of them are allocated once, at
/// their size.
#[test]
fn strings_for_the_library_are_allocated_at_their_size() {
    let z = terminated(b"abc").unwrap().unwrap();
    assert_eq!((z.as_slice(), z.capacity()), (&b"abc\0"[..], 4));
    let zs = [b"a\0".to_vec(), b"bc\0".to_vec()];
    let list = c_list(&zs).unwrap();
    assert_eq!(list.capacity(), 3);
    assert_eq!(
        list,
        [
            zs[0].as_ptr().cast_mut().cast::<c_char>(),
            zs[1].as_ptr().cast_mut().cast::<c_char>(),
            ptr::null_mut(),
        ]
    );
}
