use curl_core::libraries::Ed25519;

use crate::ED25519;

fn hex(text: &str) -> Vec<u8> {
    let text = text.trim();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(DIGITS[(n >> (18 - 6 * i) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// RFC 8032's test vectors 1 and 2 (section 7.1).
#[test]
fn signs_rfc_8032_s_vectors() {
    for (key, message, signature) in [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555\
             fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
    ] {
        let key: [u8; 32] = hex(key).try_into().unwrap();
        let made = ED25519.sign(&key, &hex(message)).unwrap();
        assert_eq!(made.as_slice(), hex(signature));
    }
}

/// Test 5001's signature base, signed with the key of tests/data, is the
/// signature the test expects.
#[test]
fn signs_test_5001_s_base_with_the_test_key() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/data/data-httpsig-ed25519.key"
    );
    let key: [u8; 32] = hex(&std::fs::read_to_string(path).unwrap())
        .try_into()
        .unwrap();
    let base = "\"@method\": GET\n\
                \"@authority\": example.com:8000\n\
                \"@path\": /5001/resource\n\
                \"@query\": ?action=read\n\
                \"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"@query\");\
                created=0;keyid=\"my-key-1\";alg=\"ed25519\"";
    let made = ED25519.sign(&key, base.as_bytes()).unwrap();
    assert_eq!(
        base64(&made),
        "RQniOeqmwdRzGvoDIMJ8XJha75evJWgqo5/66EeuJeEGczZtnP2U/F52Lzd/y7Vd1DCb8oUcCKHrKi2VJI7lBA=="
    );
}
