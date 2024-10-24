use std::{
    collections::VecDeque,
    sync::mpsc::{self, Receiver, Sender},
    thread,
};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use tracing::{info, instrument};

type Data = String;
type Payload = Vec<u8>;

#[derive(Debug)]
enum XferType {
    Read,
    Write,
    Completion,
}
struct Packet {
    t: XferType,
    p: Option<Payload>,
}

type Key256 = [u8; 256 / 8];

const AES_KEY_256: Key256 = *b"MyVeryLong256bitAesEncryptionKey";

struct Tx {
    tx: Sender<Packet>,
    aes_engine: Aes256Gcm,
    iv: u128,
}
impl Tx {
    pub fn new(tx: Sender<Packet>, key: Key256) -> Tx {
        Tx {
            tx,
            aes_engine: Aes256Gcm::new(&key.into()),
            iv: 1,
        }
    }

    #[instrument(level = "info", name = "Send", skip_all)]
    pub fn send(&mut self, mut pkt: Packet) {
        info!("{:?} Packet, payload = {:x?}", pkt.t, pkt.p);
        if let Some(payload) = &mut pkt.p {
            self.encrypt(payload);
        }
        self.tx.send(pkt).expect("RP TX error");
    }

    #[instrument(level = "info", name = "Encrypt", skip_all)]
    fn encrypt(&mut self, payload: &mut Payload) {
        let nonce = &self.iv.to_le_bytes()[0..12]; // convert u128 to &[u8] with 12 bytes (= 96 bits)
        let ciphertext = self
            .aes_engine
            .encrypt(Nonce::from_slice(nonce), payload.as_ref())
            .expect("RP encryption error");
        info!(
            "(non-empty payload) IV = {}, ciphertext + auth tag = {:x?}",
            self.iv, ciphertext
        );
        self.iv += 1;
        *payload = ciphertext;
    }
}
struct Rx {
    rx: Receiver<Packet>,
    aes_engine: Aes256Gcm,
    iv: u128,
}
impl Rx {
    pub fn new(rx: Receiver<Packet>, key: Key256) -> Rx {
        Rx {
            rx,
            aes_engine: Aes256Gcm::new(&key.into()),
            iv: 1,
        }
    }

    #[instrument(level = "info", name = "Receive", skip_all)]
    pub fn receive(&mut self) -> Option<Packet> {
        if let Ok(mut pkt) = self.rx.recv() {
            info!("{:?} Packet, payload = {:x?}", pkt.t, pkt.p);
            if let Some(payload) = &mut pkt.p {
                self.decrypt(payload)
            }
            Some(pkt)
        } else {
            None
        }
    }
    #[instrument(level = "info", name = "Decrypt", skip_all)]
    fn decrypt(&mut self, payload: &mut Payload) {
        let nonce = &self.iv.to_le_bytes()[0..12]; // convert u128 to &[u8] with 12 bytes (= 96 bits)
        let plaintext = self
            .aes_engine
            .decrypt(Nonce::from_slice(nonce), payload.as_ref())
            .expect("EP decryption error");
        info!(
            "(non-empty payload) IV = {}, plaintext = {:x?}",
            self.iv, plaintext
        );
        self.iv += 1;
        *payload = plaintext;
    }
}

struct RootPort {
    tx: Tx,
    rx: Rx,
}
impl RootPort {
    pub fn new(tx: Sender<Packet>, rx: Receiver<Packet>, key: Key256) -> RootPort {
        RootPort {
            tx: Tx::new(tx, key),
            rx: Rx::new(rx, key),
        }
    }
    #[instrument(level = "info", name = "Read", skip_all)]
    pub fn read(&mut self) -> Data {
        let pkt = Packet {
            t: XferType::Read,
            p: None,
        };
        self.tx.send(pkt);
        let payload = self
            .rx
            .receive()
            .expect("RP RX failed, nothing to receive!")
            .p
            .expect("RP RX received empty payload!");
        String::from_utf8(payload).expect("RP RX failed, can't convert payload to String!")
    }
    #[instrument(level = "info", name = "Write", skip_all)]
    pub fn write(&mut self, data: Data) {
        let pkt = Packet {
            t: XferType::Write,
            p: Some(data.into_bytes()),
        };
        self.tx.send(pkt);
    }
}

struct Endpoint {
    tx: Tx,
    rx: Rx,
}
impl Endpoint {
    pub fn new(tx: Sender<Packet>, rx: Receiver<Packet>, key: Key256) -> Endpoint {
        Endpoint {
            tx: Tx::new(tx, key),
            rx: Rx::new(rx, key),
        }
    }
    #[instrument(level = "info", name = "Respond", skip_all)]
    pub fn respond(&mut self, p: Payload) {
        let cpl = Packet {
            t: XferType::Completion,
            p: Some(p),
        };
        self.tx.send(cpl);
    }
}

#[instrument(level = "info", name = "Host", skip_all)]
fn host_model(tx: Sender<Packet>, rx: Receiver<Packet>) {
    let mut rp = RootPort::new(tx, rx, AES_KEY_256);
    rp.write("Hello".to_string());
    rp.write("World".to_string());
    println!("{:?}", rp.read());
    println!("{:?}", rp.read());
}

#[instrument(level = "info", name = "Endpoint", skip_all)]
fn device_model(tx: Sender<Packet>, rx: Receiver<Packet>) {
    let mut fifo = VecDeque::new();

    let mut ep = Endpoint::new(tx, rx, AES_KEY_256);

    while let Some(pkt) = ep.rx.receive() {
        match pkt.t {
            XferType::Read => {
                let payload = fifo.pop_front().expect("Reading from empty FIFO!");
                ep.respond(payload);
            }
            XferType::Write => {
                fifo.push_back(pkt.p.expect("Writing empty Payload!"));
            }
            XferType::Completion => unimplemented!(),
        }
    }
}

fn main() {
    let format = tracing_subscriber::fmt::format()
        .with_target(false)
        .without_time();
    tracing_subscriber::fmt().event_format(format).init();

    let (downstream_tx, downstream_rx) = mpsc::channel();
    let (upstream_tx, upstream_rx) = mpsc::channel();

    let host = thread::spawn(move || host_model(downstream_tx, upstream_rx));
    let ep = thread::spawn(move || device_model(upstream_tx, downstream_rx));

    host.join().unwrap();
    ep.join().unwrap();
}
