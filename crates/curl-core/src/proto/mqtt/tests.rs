use super::*;
use crate::conn::io::Conversation;
use crate::proto::raw::wire::{Ran, against};

/// Lengths encode in seven bits a byte, low first, at most four bytes.
#[test]
fn lengths_encode_as_mqtt_has_them() {
    assert_eq!(encode_len(0), ([0, 0, 0, 0], 0));
    assert_eq!(encode_len(127), ([127, 0, 0, 0], 1));
    assert_eq!(encode_len(128), ([0x80, 1, 0, 0], 2));
    assert_eq!(encode_len(16383), ([0xff, 0x7f, 0, 0], 2));
    assert_eq!(encode_len(MAX_MESSAGE), ([0xff, 0xff, 0xff, 0x7f], 4));
    // Past four bytes C stops, the rest lost: the packet's size check
    // refuses it first.
    assert_eq!(encode_len(MAX_MESSAGE + 1).1, 4);
    for len in [0, 1, 127, 128, 300, 16384, 2_097_151, MAX_MESSAGE] {
        let (bytes, n) = encode_len(len);
        assert_eq!(decode_len(&bytes[..n.max(1)]), Some(len), "{len}");
    }
}

/// A length that runs past four bytes, or stops in the middle, is no
/// length.
#[test]
fn a_bad_length_is_refused() {
    assert_eq!(decode_len(&[0x80, 0x80, 0x80, 0x80, 0x01]), None);
    assert_eq!(decode_len(&[0x80]), None);
    assert_eq!(decode_len(&[]), None);
    assert_eq!(decode_len(&[0x05, 0xff]), Some(5));
}

const ID: &[u8; 12] = b"curlABCDEFGH";

/// CONNECT says the protocol's name and level, a clean session, a
/// keep-alive of 60 seconds and the client's id, then the user and the
/// password, each flagged, if given.
#[test]
fn connect_carries_the_id_and_the_login() {
    let bare = connect_packet(ID, b"", b"").unwrap();
    let mut want = vec![
        0x10, 24, 0, 4, b'M', b'Q', b'T', b'T', 4, 0x02, 0, 0x3c, 0, 12,
    ];
    want.extend_from_slice(ID);
    assert_eq!(bare, want);
    let both = connect_packet(ID, b"u", b"pw").unwrap();
    assert_eq!(both[1], 24 + 3 + 4);
    assert_eq!(both[9], 0x02 | 0x80 | 0x40);
    assert!(both.ends_with(b"\0\x01u\0\x02pw"));
    let user = connect_packet(ID, b"u", b"").unwrap();
    assert_eq!(user[9], 0x82);
    assert!(user.ends_with(b"\0\x01u"));
}

/// A user or password longer than 16 bits count is refused.
#[test]
fn a_login_too_long_is_refused() {
    let long = vec![b'a'; 0x10000];
    assert_eq!(
        connect_packet(ID, &long, b""),
        Err(ConnectRefused::UserTooLong(0x10000))
    );
    assert_eq!(
        connect_packet(ID, b"u", &long),
        Err(ConnectRefused::PasswordTooLong(0x10000))
    );
    assert!(connect_packet(ID, &long[1..], &long[1..]).is_ok());
}

/// SUBSCRIBE says its id, the topic and QoS 0; PUBLISH the topic and the
/// payload.
#[test]
fn subscribe_and_publish_packets() {
    assert_eq!(
        subscribe_packet(b"1190", 1).unwrap(),
        b"\x82\x09\x00\x01\x00\x041190\x00"
    );
    assert_eq!(subscribe_packet(b"t", 0x1234).unwrap()[2..4], [0x12, 0x34]);
    assert_eq!(
        publish_packet(b"1191", b"something").unwrap(),
        b"\x30\x0f\x00\x041191something"
    );
    assert_eq!(publish_packet(b" ", b"").unwrap(), b"\x30\x03\x00\x01 ");
    let topic = vec![b'A'; 300];
    let long = subscribe_packet(&topic, 1).unwrap();
    assert_eq!(long[1..3], [0xb1, 0x02]);
}

const CONNACK: &[u8] = b"\x20\x02\x00\x00";
const SUBACK: &[u8] = b"\x90\x03\x00\x01\x00";
const PUBLISH: &[u8] = b"\x30\x0d\x00\x05topichello\n";
/// What C delivers of it: all its remaining length, the topic too.
const DELIVERED: &[u8] = b"\x00\x05topichello\n";
const DISCONNECT: &[u8] = b"\xe0\x00";

/// A server that acknowledges the CONNECT, then answers the next packet
/// with `rest`.
fn server(rest: &[u8]) -> Conversation {
    Conversation::replies(&[CONNACK, rest], true).per_send()
}

fn subscribed(rest: &[u8]) -> (Vec<u8>, Ran) {
    against(server(rest), "mqtt://127.0.0.1:PORT/topic", |_| {})
}

fn then(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// A subscription delivers each PUBLISH's payload until the server says
/// DISCONNECT.
#[test]
fn a_subscription_reads_until_disconnect() {
    let (said, ran) = subscribed(&then(&[SUBACK, PUBLISH, PUBLISH, DISCONNECT]));
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert_eq!(ran.body, [DELIVERED, DELIVERED].concat());
    // The CONNECT, its id `curl` and eight letters or digits, then the
    // SUBSCRIBE.
    assert_eq!(
        said[..18],
        *b"\x10\x18\x00\x04MQTT\x04\x02\x00\x3c\x00\x0ccurl"
    );
    assert!(said[18..26].iter().all(u8::is_ascii_alphanumeric));
    assert_eq!(said[26..], *b"\x82\x0a\x00\x01\x00\x05topic\x00");
    let id = std::str::from_utf8(&said[14..26]).unwrap();
    assert!(
        ran.text.contains(&format!("Using client id '{id}'\n")),
        "{}",
        ran.text
    );
    assert!(ran.text.contains("Got DISCONNECT\n"), "{}", ran.text);
    assert!(
        ran.text.contains("Remaining length: 13 bytes\n"),
        "{}",
        ran.text
    );
}

/// A PUBLISH may come before the SUBACK.
#[test]
fn a_publish_may_come_before_the_suback() {
    let (_, ran) = subscribed(&then(&[PUBLISH, SUBACK, DISCONNECT]));
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert_eq!(ran.body, DELIVERED);
}

/// The server's close cuts a PUBLISH short.
#[test]
fn a_short_publish_is_a_partial_file() {
    let (_, ran) = subscribed(&then(&[SUBACK, &PUBLISH[..8]]));
    assert_eq!(
        ran.result,
        Some(Err(ErrorKind::PartialFile)),
        "{}",
        ran.text
    );
    assert!(ran.text.contains("server disconnected\n"), "{}", ran.text);
}

/// The server's close between packets ends the transfer as a failed
/// read.
#[test]
fn a_close_between_packets_is_a_failed_read() {
    let (_, ran) = subscribed(SUBACK);
    assert_eq!(ran.result, Some(Err(ErrorKind::RecvError)), "{}", ran.text);
    assert!(
        ran.text.contains("Connection disconnected\n"),
        "{}",
        ran.text
    );
}

/// A CONNACK that refuses the connection, or is of the wrong length,
/// fails the transfer as C says it.
#[test]
fn a_bad_connack_fails() {
    for (ack, says) in [
        (&b"\x20\x02\x00\x05"[..], "Expected 0000 but got 0005\n"),
        (
            b"\x20\x03\x00\x00\x00",
            "CONNACK expected Remaining Length 2, got 3\n",
        ),
    ] {
        let talk = Conversation::replies(&[ack], true).per_send();
        let (_, ran) = against(talk, "mqtt://127.0.0.1:PORT/topic", |_| {});
        assert_eq!(ran.result, Some(Err(ErrorKind::WeirdServerReply)));
        assert!(ran.text.contains(says), "{}", ran.text);
    }
}

/// A SUBACK for another packet id fails the transfer.
#[test]
fn a_suback_for_another_packet_fails() {
    let (_, ran) = subscribed(b"\x90\x03\x00\x02\x00");
    assert_eq!(ran.result, Some(Err(ErrorKind::WeirdServerReply)));
}

/// A PINGRESP or DISCONNECT with a length or reserved bits is malformed.
#[test]
fn a_malformed_disconnect_fails() {
    let (_, ran) = subscribed(&then(&[SUBACK, b"\xe0\x01\x00"]));
    assert_eq!(ran.result, Some(Err(ErrorKind::WeirdServerReply)));
    let says = "Broker sent malformed DISCONNECT (remaining_length=1, header byte=0xe0)\n";
    assert!(ran.text.contains(says), "{}", ran.text);
    let talk = Conversation::replies(&[b"\xd1\x00"], true).per_send();
    let (_, ran) = against(talk, "mqtt://127.0.0.1:PORT/topic", |_| {});
    let says = "Broker sent malformed PINGRESP (remaining_length=0, header byte=0xd1)\n";
    assert!(ran.text.contains(says), "{}", ran.text);
}

/// A remaining length past four bytes fails the transfer.
#[test]
fn a_length_past_four_bytes_fails() {
    let (_, ran) = subscribed(&then(&[SUBACK, b"\x30\xff\xff\xff\x80\x00"]));
    assert_eq!(ran.result, Some(Err(ErrorKind::WeirdServerReply)));
}

/// A PUBLISH larger than the transfer may deliver fails before any of it
/// is.
#[test]
fn a_publish_past_the_most_allowed_fails() {
    let talk = server(&then(&[SUBACK, PUBLISH, DISCONNECT]));
    let (_, ran) = against(talk, "mqtt://127.0.0.1:PORT/topic", |o| {
        o.flow.make_mut().unwrap().max_filesize = std::num::NonZeroU64::new(10);
    });
    assert_eq!(ran.result, Some(Err(ErrorKind::FilesizeExceeded)));
    assert!(
        ran.text.contains("Maximum file size exceeded\n"),
        "{}",
        ran.text
    );
    assert!(ran.body.is_empty());
}

fn posting(payload: &[u8]) -> impl FnOnce(&mut crate::options::Options) {
    let payload = payload.to_vec();
    move |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(payload).unwrap());
    }
}

/// A post PUBLISHes its bytes to the topic and says DISCONNECT, and is
/// done.
#[test]
fn a_post_publishes_and_disconnects() {
    let talk = Conversation::replies(&[CONNACK], false).per_send();
    let (said, ran) = against(
        talk,
        "mqtt://u:pw@127.0.0.1:PORT/t%20x",
        posting(b"something"),
    );
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    let connect = said[1] as usize + 2;
    assert_eq!(said[9], 0xc2, "the user and password are flagged");
    assert!(said[..connect].ends_with(b"\0\x01u\0\x02pw"));
    assert_eq!(said[connect..], *b"\x30\x0e\x00\x03t xsomething\xe0\x00");
}

/// A post whose packets the connection takes a few bytes at a time sends
/// them whole, in order.
#[test]
fn packets_taken_in_pieces_go_whole() {
    let three = std::num::NonZeroUsize::new(3).unwrap();
    let talk = Conversation::replies(&[CONNACK], false)
        .per_send()
        .taking(three)
        .stalling_sends_after(2, 2);
    let (said, ran) = against(talk, "mqtt://127.0.0.1:PORT/top", posting(b"payload"));
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert!(
        said.ends_with(b"\x30\x0c\x00\x03toppayload\xe0\x00"),
        "{said:?}"
    );
    assert_eq!(said[1] as usize + 2, said.len() - 14 - 2);
}

/// A post whose DISCONNECT the connection takes a byte at a time, and
/// not at once, ends only once all of it has gone.
#[test]
fn a_post_ends_once_its_disconnect_has_gone() {
    let one = std::num::NonZeroUsize::new(1).unwrap();
    // The CONNECT's 26 bytes, the PUBLISH's 14 and the DISCONNECT's
    // first.
    let talk = Conversation::replies(&[CONNACK], false)
        .per_send()
        .taking(one)
        .stalling_sends_after(26 + 14 + 1, 1);
    let (said, ran) = against(talk, "mqtt://127.0.0.1:PORT/top", posting(b"payload"));
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert_eq!(said.len(), 26 + 14 + 2, "{said:?}");
    assert!(said.ends_with(b"payload\xe0\x00"), "{said:?}");
}

/// A post of no payload, as the application gave none, is refused.
#[test]
fn a_post_without_bytes_is_refused() {
    let talk = Conversation::replies(&[CONNACK], false).per_send();
    let (_, ran) = against(talk, "mqtt://127.0.0.1:PORT/t", |o| {
        o.method = Method::Post;
    });
    assert_eq!(ran.result, Some(Err(ErrorKind::BadFunctionArgument)));
}

/// A URL without a topic, or with a control byte in it, is refused.
#[test]
fn a_topic_is_needed() {
    let talk = Conversation::replies(&[CONNACK], false).per_send();
    let (_, ran) = against(talk, "mqtt://127.0.0.1:PORT/", |_| {});
    assert_eq!(ran.result, Some(Err(ErrorKind::UrlMalformat)));
    assert!(
        ran.text
            .contains("No MQTT topic found. Forgot to URL encode it?\n"),
        "{}",
        ran.text
    );
    let talk = Conversation::replies(&[CONNACK], false).per_send();
    let (_, ran) = against(talk, "mqtt://127.0.0.1:PORT/a%00b", |_| {});
    assert_eq!(ran.result, Some(Err(ErrorKind::UrlMalformat)));
}

/// A user name past 16 bits is refused as CONNECT is made, nothing sent.
#[test]
fn a_long_user_fails_the_connect() {
    let talk = Conversation::replies(&[CONNACK], false).per_send();
    let user = "a".repeat(0x10000);
    let url = format!("mqtt://{user}@127.0.0.1:PORT/t");
    let (said, ran) = against(talk, &url, |_| {});
    assert_eq!(ran.result, Some(Err(ErrorKind::WeirdServerReply)));
    assert!(
        ran.text.contains("Username too long: [65536]\n"),
        "{}",
        ran.text
    );
    assert!(
        ran.text.contains("Error 8 sending MQTT CONNECT request\n"),
        "{}",
        ran.text
    );
    assert!(said.is_empty());
}

/// The states are numbered and named as C's are.
#[test]
fn the_states_are_c_s() {
    let states = [
        State::First,
        State::RemainingLength,
        State::Connack,
        State::Suback,
        State::SubackComing,
        State::PubWait,
        State::PubRemain,
        State::PostDrain,
        State::DisconnectDrain,
        State::Unset,
    ];
    for (i, s) in states.iter().enumerate() {
        assert_eq!(usize::from(s.number()), i);
    }
    assert_eq!(State::PubWait.name(), "MQTT_PUBWAIT");
    assert_eq!(State::Unset.name(), "NOT A STATE");
}

const ANSWERS: &[&[u8]] = &[
    b"\x90\x03\x00\x01\x00\x30\x0d\x00\x05topichello\n\xe0\x00",
    b"\x30\x0d\x00\x05topichello\n\x90\x03\x00\x01\x00\xd0\x00\xe0\x00",
    b"\x90\x03\x00\x01\x00\x30\x80\x01\x00\x01t",
];

proptest::proptest! {
    #![proptest_config(crate::untrusted::config(48))]

    /// Whatever the server answers a subscription with, the transfer
    /// ends, with an error or not, and never panics.
    #[test]
    fn any_answer_ends_the_transfer(answer in crate::untrusted::mutated(ANSWERS)) {
        let (_, ran) = subscribed(&answer);
        proptest::prop_assert!(ran.result.is_some());
    }

    /// Any bytes decode to a length or are refused.
    #[test]
    fn any_bytes_are_a_length_or_refused(bytes in proptest::collection::vec(0u8.., 0..8)) {
        let _ = decode_len(&bytes);
    }
}
