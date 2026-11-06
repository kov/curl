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

/// A CONNECT past MQTT's largest message is refused before its user's
/// length is looked at, as C checks them; one of exactly that size is not.
#[test]
fn a_connect_past_the_largest_message_is_refused_first() {
    // A type byte, four of length, ten of variable header, the id's two
    // and its own, and the user's two.
    let n = MAX_MESSAGE - 1 - 4 - 10 - 2 - CLIENT_ID_LEN - 2;
    assert_eq!(connect_len(n, 0), MAX_MESSAGE);
    let huge = vec![0u8; n + 1];
    assert_eq!(
        connect_packet(ID, &huge[..n], b""),
        Err(ConnectRefused::UserTooLong(n))
    );
    assert_eq!(
        connect_packet(ID, &huge, b""),
        Err(ConnectRefused::TooLarge)
    );
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
    // The topic's length, in two bytes.
    assert_eq!(long[5..7], [0x01, 0x2c]);
    assert_eq!(long.len(), 3 + 2 + 2 + 300 + 1);
    let long = publish_packet(&topic, b"p").unwrap();
    assert_eq!(long[1..5], [0xaf, 0x02, 0x01, 0x2c]);
    assert_eq!(long.len(), 3 + 2 + 300 + 1);
    // Each made in one allocation of its size.
    assert_eq!(long.capacity(), long.len());
    let sub = subscribe_packet(&topic, 1).unwrap();
    assert_eq!(sub.capacity(), sub.len());
    let short = publish_packet(b"t", b"p").unwrap();
    assert_eq!(short.capacity(), short.len());
}

/// A PUBLISH whose length leaves room for its header is made; one a
/// byte longer is refused (`mqtt_publish`).
#[test]
fn a_publish_past_the_largest_message_is_refused() {
    // Four bytes of length and one of type.
    let most = MAX_MESSAGE - 4 - 1;
    let payload = vec![0u8; most - 2 - 1];
    assert_eq!(publish_packet(b"t", &payload).unwrap().len(), MAX_MESSAGE);
    let payload = vec![0u8; most - 2];
    assert_eq!(publish_packet(b"t", &payload), Err(ErrorKind::TooLarge));
}

/// The CONNECT's length is the packet's: a type byte, the length's
/// bytes, ten of variable header, the id's and the login's.
#[test]
fn a_connect_is_as_long_as_its_length_says() {
    for (user, password) in [
        (&b""[..], &b""[..]),
        (b"u", b""),
        (b"", b"p"),
        (b"user", b"secret"),
        // A remaining length of 128, the first to take two bytes.
        (&[b'a'; 102][..], b""),
        (&[b'a'; 200][..], b"p"),
    ] {
        let packet = connect_packet(ID, user, password).unwrap();
        assert_eq!(connect_len(user.len(), password.len()), packet.len());
    }
    assert_eq!(connect_len(0, 0), 1 + 1 + 10 + 2 + CLIENT_ID_LEN);
    assert_eq!(connect_len(1, 1), 1 + 1 + 10 + 2 + CLIENT_ID_LEN + 3 + 3);
    assert_eq!(
        connect_len(200, 0),
        1 + 2 + 10 + 2 + CLIENT_ID_LEN + 2 + 200
    );
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
    assert!(!ran.text.contains("Received ping response"), "{}", ran.text);
    // The debug build says each state, and the one after the first.
    if cfg!(feature = "debug-hooks") {
        assert!(
            ran.text
                .contains("MQTT_FIRST (from MQTT_PUB_REMAIN) (next is MQTT_PUBWAIT)\n"),
            "{}",
            ran.text
        );
        assert!(
            ran.text
                .contains("MQTT_PUB_REMAIN (from MQTT_PUBWAIT) (next is )\n"),
            "{}",
            ran.text
        );
    }
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

/// Without a TLS library, `mqtts:` is a scheme the build leaves out,
/// nothing sent.
#[test]
fn mqtts_needs_a_tls_library() {
    let talk = Conversation::replies(&[], false);
    let (said, ran) = against(talk, "mqtts://127.0.0.1:PORT/x", |_| {});
    assert_eq!(
        ran.result,
        Some(Err(crate::error::ErrorKind::UnsupportedProtocol)),
        "{}",
        ran.text
    );
    assert!(said.is_empty());
}

/// A connection reset while a packet is read fails the transfer, the
/// reason said once, by the layer that saw it.
#[test]
fn a_reset_fails_with_the_socket_s_reason() {
    let talk = Conversation::replies(&[CONNACK, SUBACK], false)
        .per_send()
        .resetting();
    let (_, ran) = against(talk, "mqtt://127.0.0.1:PORT/topic", |_| {});
    assert_eq!(ran.result, Some(Err(ErrorKind::RecvError)), "{}", ran.text);
    #[cfg(unix)]
    let said = ran.text.matches("Recv failure: Connection reset by peer\n");
    // Winsock's words, from C's table (`get_winsock_error`).
    #[cfg(windows)]
    let said = ran.text.matches("Recv failure: Connection was reset\n");
    assert_eq!(said.count(), 1, "{}", ran.text);
}

/// The sizes of the pieces a writer was given.
#[derive(Clone, Default)]
struct Pieces(std::sync::Arc<std::sync::Mutex<Vec<usize>>>);

impl crate::handler::WriteHandler for Pieces {
    fn write(&self, _: &mut crate::multi::TransferCx<'_>, body: &[u8]) -> crate::handler::Write {
        self.0.lock().unwrap().push(body.len());
        crate::handler::Write::Took(body.len())
    }
}

/// A PUBLISH whose length takes two bytes is delivered 4 KiB at a time,
/// as C reads it; one exactly as large as the transfer may deliver is.
#[test]
fn a_long_publish_is_delivered_in_pieces() {
    let payload = vec![b'p'; 5000];
    // Two bytes of topic length, five of topic.
    let publish = [&b"\x30\x8f\x27\x00\x05topic"[..], &payload].concat();
    let talk = server(&then(&[SUBACK, &publish, DISCONNECT]));
    let pieces = Pieces::default();
    let p = pieces.clone();
    let (_, ran) = against(talk, "mqtt://127.0.0.1:PORT/topic", |o| {
        o.callbacks.write = Some(crate::handler::Handler::write(p).unwrap());
        o.flow.make_mut().unwrap().max_filesize = std::num::NonZeroU64::new(5007);
    });
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert!(
        ran.text.contains("Remaining length: 5007 bytes\n"),
        "{}",
        ran.text
    );
    let pieces = pieces.0.lock().unwrap();
    assert_eq!(pieces.iter().sum::<usize>(), 2 + 5 + 5000);
    assert_eq!(pieces[0], 4096, "{pieces:?}");
}

/// A topic of 16 bits' length is subscribed to; one longer is refused.
#[test]
fn a_topic_past_16_bits_is_refused() {
    let longest = "t".repeat(0xffff);
    let talk = server(&then(&[SUBACK, DISCONNECT]));
    let (said, ran) = against(talk, &format!("mqtt://127.0.0.1:PORT/{longest}"), |_| {});
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert!(said.ends_with(&[longest.as_bytes(), b"\0"].concat()));
    let talk = server(&then(&[SUBACK, DISCONNECT]));
    let (said, ran) = against(talk, &format!("mqtt://127.0.0.1:PORT/{longest}t"), |_| {});
    assert_eq!(
        ran.result,
        Some(Err(ErrorKind::UrlMalformat)),
        "{}",
        ran.text
    );
    assert!(ran.text.contains("Too long MQTT topic\n"), "{}", ran.text);
    // Found as the SUBSCRIBE is made, after the CONNECT, as C finds it.
    assert_eq!(said[0], 0x10, "{said:?}");
    assert!(!said.contains(&0x82), "{said:?}");
}

/// Bytes the application lends are published as they are.
#[test]
fn lent_bytes_are_published() {
    struct Lends(Vec<u8>);
    impl crate::handler::LentBytes for Lends {
        fn size(&self) -> u64 {
            self.0.len() as u64
        }
        fn copy_at(&self, at: u64, buf: &mut [u8]) -> usize {
            let rest = &self.0[usize::try_from(at).unwrap()..];
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            n
        }
    }
    // Past one piece of the copy's.
    let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let lent = crate::handler::Handler::lent(Lends(payload.clone())).unwrap();
    let talk = Conversation::replies(&[CONNACK], false).per_send();
    let (said, ran) = against(talk, "mqtt://127.0.0.1:PORT/t", |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Lent(lent);
    });
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    let publish = [&b"\x30\x8b\x27\x00\x01t"[..], &payload, b"\xe0\x00"].concat();
    assert!(said.ends_with(&publish), "{:?}", &said[..40]);
}

/// Quiet for the upkeep interval, the client pings once, and takes the
/// server's answer.
#[test]
fn an_idle_subscription_pings_once() {
    let talk = Conversation::replies(&[CONNACK, SUBACK], false).per_send();
    let (said, ran) = against(talk, "mqtt://127.0.0.1:PORT/topic", |o| {
        o.limits.reuse.upkeep = crate::options::UpkeepInterval(std::time::Duration::from_secs(1));
        o.limits.total = crate::time::TimeLimit::from_millis(3500);
    });
    assert_eq!(
        ran.result,
        Some(Err(ErrorKind::OperationTimedout)),
        "{}",
        ran.text
    );
    let pings = said.windows(2).filter(|w| *w == b"\xc0\x00").count();
    assert_eq!(pings, 1, "{said:?}");
    assert!(
        ran.text.contains("mqtt_ping: sent ping request.\n"),
        "{}",
        ran.text
    );
    // An interval of none never pings.
    let talk = Conversation::replies(&[CONNACK, SUBACK], false).per_send();
    let (said, _) = against(talk, "mqtt://127.0.0.1:PORT/topic", |o| {
        o.limits.reuse.upkeep = crate::options::UpkeepInterval(std::time::Duration::ZERO);
        o.limits.total = crate::time::TimeLimit::from_millis(3500);
    });
    assert!(!said.ends_with(b"\xc0\x00"), "{said:?}");
}

/// The server's PINGRESP is said, and the subscription waits on.
#[test]
fn a_ping_response_is_taken() {
    let talk = Conversation::replies(&[CONNACK, &then(&[SUBACK, b"\xd0\x00", DISCONNECT])], true)
        .per_send();
    let (_, ran) = against(talk, "mqtt://127.0.0.1:PORT/topic", |_| {});
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert!(
        ran.text.contains("Received ping response.\n"),
        "{}",
        ran.text
    );
}

/// While the exchange goes on the transfer waits for the server's
/// bytes, or for room to send what of a packet is left.
#[test]
fn the_exchange_waits_on_its_socket() {
    use crate::libraries::{Libraries, SharedLibraries};
    use crate::multi::NoEvents;
    for stalled in [false, true] {
        let mut talk = Conversation::replies(&[CONNACK], false).per_send();
        if stalled {
            talk = talk.stalling_sends_after(1, 1000);
        }
        let mut m = crate::proto::raw::wire::serving(&[&talk]);
        let mut e = crate::easy::Easy::new();
        e.set_libraries(SharedLibraries::new(Libraries::NONE).unwrap());
        let url = format!("mqtt://127.0.0.1:{}/topic", crate::proto::raw::wire::PORT);
        e.options_mut().set_url(Some(url.as_bytes())).unwrap();
        m.add(Box::new(e), (), &mut NoEvents).unwrap();
        for _ in 0..5 {
            m.perform(&mut NoEvents).unwrap();
        }
        let mut seen = Vec::new();
        m.sockets(&mut NoEvents, |_, events| seen.push(events))
            .unwrap();
        let want = if stalled { Events::OUT } else { Events::IN };
        assert_eq!(seen, [want], "stalled {stalled}");
    }
}

/// A paused writer holds a PUBLISH until it is taken.
#[test]
fn a_paused_publish_is_held_until_taken() {
    let talk = server(&then(&[SUBACK, PUBLISH, DISCONNECT]));
    let took = crate::proto::raw::wire::paused_then_taken(&talk, "mqtt://127.0.0.1:PORT/topic");
    assert_eq!(took, DELIVERED);
}

/// A redirect from HTTP to another host takes the application's login
/// there only if it lets it go anywhere (`Curl_auth_allowed_to_host`).
#[test]
fn the_application_s_login_stays_with_the_first_host() {
    use crate::options::{Follow, Login, Protocols};
    use crate::proto::raw::wire::{PORT, serving, transfer};
    for unrestricted in [false, true] {
        let moved = format!(
            "HTTP/1.1 302 Moved\r\nLocation: mqtt://other.test:{PORT}/topic\r\n\
             Connection: close\r\nContent-Length: 0\r\n\r\n"
        );
        let http = Conversation::new(moved.as_bytes(), true);
        let mqtt = server(&then(&[SUBACK, PUBLISH, DISCONNECT]));
        let mut m = serving(&[&http, &mqtt]);
        let entry = format!("other.test:{PORT}:127.0.0.1");
        let url = format!("http://127.0.0.1:{PORT}/a");
        let ran = transfer(&mut m, &url, |o| {
            o.http.follow = Follow::All;
            o.http.unrestricted_auth = unrestricted;
            o.schemes.make_mut().unwrap().redirect = Protocols::of(&["mqtt"]).unwrap();
            o.resolve.set([entry.as_bytes()]).unwrap();
            *o.login.make_mut().unwrap() = Login::from_pair(b"user:secret").unwrap();
        });
        assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
        let said = mqtt.received();
        let has = said.windows(6).any(|w| w == b"secret");
        assert_eq!(has, unrestricted, "{said:?}");
    }
}

/// Packets read a byte at a time are taken whole, each in turn.
#[test]
fn packets_read_a_byte_at_a_time_are_taken_whole() {
    let one = std::num::NonZeroUsize::new(1).unwrap();
    let talk = server(&then(&[SUBACK, PUBLISH, DISCONNECT])).giving(one);
    let (said, ran) = against(talk, "mqtt://127.0.0.1:PORT/topic", |_| {});
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert_eq!(ran.body, DELIVERED);
    assert!(said.ends_with(b"\x82\x0a\x00\x01\x00\x05topic\x00"));
}

/// unit1693: a post's CONNECT, PUBLISH and DISCONNECT over a connection
/// whose sends take what each of `t1693_run`'s scripts says. Each send is
/// offered what is left of the packet going, never more of the next
/// before it is gone; while some of it waits the transfer waits to write,
/// else to read; the CONNACK is read only once the CONNECT is gone; the
/// bytes go in order, all of them, and a send that fails fails the
/// transfer (`CURLE_SEND_ERROR`) with what went before it sent. A send C
/// says took none of it with no error is a send that would block here: a
/// socket's send takes a byte or more, or none and blocks.
#[test]
fn unit1693_partial_sends() {
    use crate::conn::io::{Events, ScriptedSend};
    use crate::proto::raw::wire::{added, serving, waits};
    const FILE: &str = "tests/unit/unit1693.c";
    let constant = |w: &str| usize::try_from(crate::c_source::constant(FILE, w)).unwrap();
    let ends = [
        constant("T1693_CONNECT_LEN"),
        constant("T1693_PUBLISH_END"),
        constant("T1693_WIRE_LEN"),
    ];
    // What follows the CONNECT, whose client id is random.
    let post: Vec<u8> = crate::c_source::table(FILE, "post[] =", |c| panic!("{c}"))
        .iter()
        .map(|b| match b.word().as_bytes() {
            [b'\'', c, b'\''] => *c,
            _ => u8::try_from(b.int()).unwrap(),
        })
        .collect();
    assert_eq!(ends[0] + post.len(), ends[2]);
    let holds = |c: &str| {
        assert_eq!(c, "!(defined(CURL_DISABLE_MQTT))");
        true
    };
    let runs = crate::c_source::calls_where(FILE, "t1693_run", holds);
    assert_eq!(runs.len(), 4);
    for run in runs {
        let name = run[0].word();
        let script: Vec<ScriptedSend> =
            crate::c_source::table(FILE, &format!("{name}[] ="), |c| panic!("{c}"))
                .iter()
                .map(|step| {
                    let step = step.group();
                    match step[1].word() {
                        "CURLE_OK" => ScriptedSend::Takes(constant(step[0].word())),
                        "CURLE_AGAIN" => ScriptedSend::Takes(0),
                        "CURLE_SEND_ERROR" => ScriptedSend::Fails,
                        other => panic!("{other}"),
                    }
                })
                .collect();
        let ok = match run[2].word() {
            "CURLE_OK" => true,
            "CURLE_SEND_ERROR" => false,
            other => panic!("{other}"),
        };
        let talk = Conversation::replies(&[CONNACK], false)
            .per_send()
            .scripted_sends(&script);
        let mut m = serving(&[&talk]);
        added(&mut m, "mqtt://127.0.0.1:PORT/test", posting(b"payload"));
        let mut result = None;
        for _ in 0..script.len() + 4 {
            m.perform(&mut crate::multi::NoEvents).unwrap();
            if let Some(done) = m.info_read() {
                result = Some(done.result);
                break;
            }
            // What the last send left of its packet; before the first,
            // the connection is still being made.
            let offered = talk.offered();
            if offered.is_empty() {
                continue;
            }
            let pending = match (offered.last(), script.get(offered.len().wrapping_sub(1))) {
                (Some(&len), Some(&ScriptedSend::Takes(took))) => took < len,
                _ => false,
            };
            let want = if pending { Events::OUT } else { Events::IN };
            assert_eq!(waits(&mut m), [want], "{name}, after {offered:?}");
        }
        assert_eq!(talk.script_left(), 0, "{name}: not all scripted sends used");
        // Each send was offered what was left of the packet going.
        let mut sent = 0;
        for (i, (&len, step)) in talk.offered().iter().zip(&script).enumerate() {
            let end = ends.iter().find(|&&e| e > sent).unwrap();
            assert_eq!(len, end - sent, "{name}: send {i} of {sent} bytes gone");
            if let ScriptedSend::Takes(took) = *step {
                sent += took.min(len);
            }
        }
        let said = talk.received();
        assert_eq!(said.len(), sent, "{name}");
        assert_eq!(said[..2], [0x10, 0x18], "{name}: the CONNECT");
        assert_eq!(said[ends[0]..], post[..sent - ends[0]], "{name}");
        if ok {
            assert_eq!(result, Some(Ok(())), "{name}");
            assert_eq!(sent, ends[2], "{name}: missing packet bytes");
        } else {
            assert_eq!(result, Some(Err(ErrorKind::SendError)), "{name}");
        }
    }
}
