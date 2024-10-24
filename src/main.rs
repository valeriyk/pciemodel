use std::{
    sync::mpsc::{self, Receiver, Sender},
    thread,
};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use tracing::{info, instrument};

type Data = String;
type Packet = Vec<u8>;
type Key256 = [u8; 256 / 8];

const AES_KEY_256: Key256 = *b"MyVeryLong256bitAesEncryptionKey";

struct RootPort {
    tx: Sender<Packet>,
    aes_engine: Aes256Gcm,
    tx_iv: u128,
}
impl RootPort {
    pub fn new(tx: Sender<Packet>, key: Key256) -> RootPort {
        RootPort {
            tx,
            aes_engine: Aes256Gcm::new(&key.into()),
            tx_iv: 1,
        }
    }
    #[instrument(level = "info", name = "Encrypt", skip_all)]
    pub fn encrypt(&mut self, data: Data) -> Packet {
        let nonce = &self.tx_iv.to_le_bytes()[0..12]; // convert u128 to &[u8] with 12 bytes (= 96 bits)
        let ciphertext = self
            .aes_engine
            .encrypt(Nonce::from_slice(nonce), data.as_bytes())
            .expect("RP encryption error");
        info!(
            "Encrypting {} with IV {}, ciphertext is {:x?}",
            data, self.tx_iv, ciphertext
        );
        self.tx_iv += 1;
        ciphertext
    }
    #[instrument(level = "info", name = "Send", skip_all)]
    pub fn send(&mut self, data: String) {
        let ciphertext = self.encrypt(data);
        self.tx.send(ciphertext).expect("RP TX error");
    }
}

struct Endpoint {
    rx: Receiver<Packet>,
    aes_engine: Aes256Gcm,
    rx_iv: u128,
}
impl Endpoint {
    pub fn new(rx: Receiver<Packet>, key: Key256) -> Endpoint {
        Endpoint {
            rx,
            aes_engine: Aes256Gcm::new(&key.into()),
            rx_iv: 1,
        }
    }
    #[instrument(level = "info", name = "Decrypt", skip_all)]
    pub fn decrypt(&mut self, ciphertext: Packet) -> Data {
        let nonce = &self.rx_iv.to_le_bytes()[0..12]; // convert u128 to &[u8] with 12 bytes (= 96 bits)
        let plaintext = self
            .aes_engine
            .decrypt(Nonce::from_slice(nonce), ciphertext.as_ref())
            .expect("EP decryption error");
        let plaintext = String::from_utf8(plaintext).expect("EP conversion to String failed");
        info!(
            "Decrypting {:x?} with IV {}, plaintext is {:?}",
            ciphertext, self.rx_iv, plaintext
        );
        self.rx_iv += 1;
        plaintext
    }
    #[instrument(level = "info", name = "Receive", skip_all)]
    pub fn receive(&mut self) -> Option<Data> {
        let ciphertext = self.rx.recv();
        match ciphertext {
            Ok(x) => Some(self.decrypt(x)),
            Err(_) => None,
        }
    }
}
impl Iterator for Endpoint {
    type Item = Data;
    fn next(&mut self) -> Option<Self::Item> {
        self.receive()
    }
}

#[instrument(level = "info", name = "Host", skip_all)]
fn host_model(tx: Sender<Packet>) {
    let mut rp = RootPort::new(tx, AES_KEY_256);
    rp.send("Hello".to_string());
    rp.send("World".to_string());
}

#[instrument(level = "info", name = "Endpoint", skip_all)]
fn device_model(rx: Receiver<Packet>) {
    let ep = Endpoint::new(rx, AES_KEY_256);
    ep.for_each(|data| println!("{}", data));
}

fn main() {
    let format = tracing_subscriber::fmt::format()
        .with_target(false)
        .without_time();
    tracing_subscriber::fmt().event_format(format).init();

    let (tx, rx) = mpsc::channel();

    let host = thread::spawn(move || host_model(tx));
    let ep = thread::spawn(move || device_model(rx));

    host.join().unwrap();
    ep.join().unwrap();
}
