use std::{
    collections::HashMap,
    ops::{Add, Sub},
};

use aead::{
    rand_core::{CryptoRng, RngCore},
    AeadCore, AeadMutInPlace, KeyInit, Nonce,
};
use generic_array::{
    sequence::{Concat, Split},
    typenum::{Unsigned, U16, U32, U8},
    ArrayLength, GenericArray,
};

pub trait DiffieHellman {
    type PublicKey: ArrayLength<u8>;
    type SecretKey: ArrayLength<u8>;
    type OutputSize: ArrayLength<u8>;

    /// Returns a new Diffie-Hellman key pair.
    fn keypair(rng: &mut (impl RngCore + CryptoRng)) -> KeyPair<Self>;

    /// Returns the output from the Diffie-Hellman calculation between the private key from the
    /// DH key pair dh_pair and the DH public key dh_pub. If the DH function rejects invalid public keys, then this
    /// function may raise an exception which terminates processing.
    fn exchange(
        pk: GenericArray<u8, Self::PublicKey>,
        sk: GenericArray<u8, Self::SecretKey>,
    ) -> GenericArray<u8, Self::OutputSize>;
}

pub type KeyPair<Dh> = (
    GenericArray<u8, <Dh as DiffieHellman>::PublicKey>,
    GenericArray<u8, <Dh as DiffieHellman>::SecretKey>,
);

pub trait DoubleRatchet {
    type Dh: DiffieHellman<OutputSize = U32>;
    type Aead: AeadMutInPlace + KeyInit<KeySize = U32>;

    const MAX_SKIP: u64;

    /// Returns a pair (32-byte root key, 32-byte chain key) as the output of applying a KDF keyed
    /// by a 32-byte root key `rk` to a Diffie-Hellman output `dh_out`.
    fn kdf_rk(
        rk: GenericArray<u8, U32>,
        dh_out: GenericArray<u8, U32>,
    ) -> (GenericArray<u8, U32>, GenericArray<u8, U32>);

    /// Returns a pair (32-byte chain key, 32-byte message key, n-byte message nonce) as the output of applying a KDF keyed by
    /// a 32-byte chain key `ck` to some constant.
    fn kdf_ck(
        ck: GenericArray<u8, U32>,
    ) -> (
        GenericArray<u8, U32>,
        GenericArray<u8, U32>,
        Nonce<Self::Aead>,
    );
}

pub struct DoubleRatchetState<D: DoubleRatchet> {
    dhs: KeyPair<D::Dh>,
    dhr: GenericArray<u8, <D::Dh as DiffieHellman>::PublicKey>,
    rk: GenericArray<u8, U32>,
    cks: GenericArray<u8, U32>,
    ckr: GenericArray<u8, U32>,
    ns: u64,
    nr: u64,
    pn: u64,
    mkskipped: HashMap<
        (GenericArray<u8, <D::Dh as DiffieHellman>::PublicKey>, u64),
        (GenericArray<u8, U32>, Nonce<D::Aead>),
    >,
}

type HeaderLen<D> = <<<D as DoubleRatchet>::Dh as DiffieHellman>::PublicKey as Add<U16>>::Output;
type Header<D> = GenericArray<u8, HeaderLen<D>>;

impl<D: DoubleRatchet> DoubleRatchetState<D> {
    pub fn init1(secret_key: GenericArray<u8, U32>, keypair: KeyPair<D::Dh>) -> Self {
        Self {
            dhs: keypair,
            dhr: GenericArray::default(),
            rk: secret_key,
            cks: GenericArray::default(),
            ckr: GenericArray::default(),
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        }
    }

    pub fn init2(
        secret_key: GenericArray<u8, U32>,
        public: GenericArray<u8, <D::Dh as DiffieHellman>::PublicKey>,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Self {
        let kp = <D::Dh as DiffieHellman>::keypair(rng);
        let dh_out = <D::Dh as DiffieHellman>::exchange(public.clone(), kp.1.clone());
        let (rk, cks) = D::kdf_rk(secret_key, dh_out);
        Self {
            dhs: kp,
            dhr: public,
            rk,
            cks,
            ckr: GenericArray::default(),
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        }
    }

    pub fn encrypt(&mut self, mut message: Vec<u8>, mut ad: Vec<u8>) -> (Header<D>, Vec<u8>)
    where
        <D::Dh as DiffieHellman>::PublicKey: Add<U16>,
        HeaderLen<D>: ArrayLength<u8>,
    {
        let (cks, mk, nonce) = D::kdf_ck(self.cks);
        self.cks = cks;

        let n = GenericArray::from(self.pn.to_le_bytes())
            .concat(GenericArray::from(self.ns.to_le_bytes()));
        let header = self.dhs.0.clone().concat(n);

        self.ns += 1;
        ad.extend_from_slice(&header);
        message.reserve(<<D::Aead as AeadCore>::TagSize as Unsigned>::USIZE);
        let mut aead = <D::Aead as KeyInit>::new(&mk);
        aead.encrypt_in_place(&nonce, &header, &mut message)
            .expect("tag size is reserved");
        (header, message)
    }

    pub fn decrypt(
        &mut self,
        header: Header<D>,
        mut message: Vec<u8>,
        mut ad: Vec<u8>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<u8>, Error>
    where
        <D::Dh as DiffieHellman>::PublicKey: Add<U16>,
        HeaderLen<D>: ArrayLength<u8> + Sub<U16, Output = <D::Dh as DiffieHellman>::PublicKey>,
        Header<D>: Split<
            u8,
            <D::Dh as DiffieHellman>::PublicKey,
            First = GenericArray<u8, <D::Dh as DiffieHellman>::PublicKey>,
            Second = GenericArray<u8, U16>,
        >,
    {
        let (pk, n) = header.clone().split();
        let (pn, ns) = <GenericArray<u8, U16> as Split<u8, U8>>::split(n);
        let pn = u64::from_le_bytes(pn.into());
        let ns = u64::from_le_bytes(ns.into());

        ad.extend_from_slice(&header);

        // check skipped
        if let Some(key) = self.mkskipped.remove(&(pk.clone(), ns)) {
            self.nr += 1;
            let mut aead = <D::Aead as KeyInit>::new(&key.0);
            aead.decrypt_in_place(&key.1, &header, &mut message)
                .map_err(|_| Error::Decryption)?;
            return Ok(message);
        }
        if pk != self.dhr {
            // if this underflows, that means pn < nr which is invalid
            let skipped = pn.checked_sub(self.nr).ok_or(Error::MissingSkipped)?;
            if skipped > D::MAX_SKIP {
                // too many skipped
                return Err(Error::TooManySkipped);
            }
            while self.nr < pn {
                let (ckr, mk, nonce) = D::kdf_ck(self.ckr);
                self.ckr = ckr;
                self.mkskipped.insert((pk.clone(), self.nr), (mk, nonce));
                self.nr += 1;
            }

            self.dhratchet(pk, rng)
        }

        let (ckr, mk, nonce) = D::kdf_ck(self.ckr);
        self.ckr = ckr;

        self.nr += 1;
        let mut aead = <D::Aead as KeyInit>::new(&mk);
        aead.decrypt_in_place(&nonce, &header, &mut message)
            .map_err(|_| Error::Decryption)?;
        Ok(message)
    }

    fn dhratchet(
        &mut self,
        pk: GenericArray<u8, <D::Dh as DiffieHellman>::PublicKey>,
        rng: &mut (impl CryptoRng + RngCore),
    ) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;

        self.dhr = pk;

        let dh_out = <D::Dh as DiffieHellman>::exchange(self.dhr.clone(), self.dhs.1.clone());
        (self.rk, self.ckr) = D::kdf_rk(self.rk, dh_out);

        self.dhs = <D::Dh as DiffieHellman>::keypair(rng);

        let dh_out = <D::Dh as DiffieHellman>::exchange(self.dhr.clone(), self.dhs.1.clone());
        (self.rk, self.cks) = D::kdf_rk(self.rk, dh_out);
    }
}

#[derive(Debug)]
pub enum Error {
    Decryption,
    TooManySkipped,
    MissingSkipped,
}

#[cfg(test)]
mod tests {
    use crate::{DiffieHellman, DoubleRatchet, DoubleRatchetState};
    use generic_array::{
        sequence::Split,
        typenum::{U32, U64},
        GenericArray,
    };
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    struct X25519;
    impl DiffieHellman for X25519 {
        type PublicKey = U32;
        type SecretKey = U32;
        type OutputSize = U32;

        fn keypair(
            rng: &mut (impl aead::rand_core::RngCore + aead::rand_core::CryptoRng),
        ) -> crate::KeyPair<Self> {
            let sk = x25519_dalek::StaticSecret::random_from_rng(rng);
            let pk = x25519_dalek::PublicKey::from(&sk);
            (pk.to_bytes().into(), sk.to_bytes().into())
        }

        fn exchange(
            pk: GenericArray<u8, Self::PublicKey>,
            sk: GenericArray<u8, Self::SecretKey>,
        ) -> GenericArray<u8, Self::OutputSize> {
            let sk: [u8; 32] = sk.into();
            let pk: [u8; 32] = pk.into();
            let sk = x25519_dalek::StaticSecret::from(sk);
            let pk = x25519_dalek::PublicKey::from(pk);
            sk.diffie_hellman(&pk).to_bytes().into()
        }
    }

    struct Settings;
    impl DoubleRatchet for Settings {
        type Dh = X25519;

        type Aead = chacha20poly1305::ChaCha20Poly1305;

        const MAX_SKIP: u64 = 10;

        fn kdf_rk(
            rk: GenericArray<u8, U32>,
            dh_out: GenericArray<u8, U32>,
        ) -> (GenericArray<u8, U32>, GenericArray<u8, U32>) {
            let mut output = GenericArray::<u8, U64>::default();
            hkdf::Hkdf::<Sha256>::new(Some(&rk), &dh_out)
                .expand(b"double-ratchet", &mut output)
                .expect("output should be small enough");
            output.split()
        }

        fn kdf_ck(
            ck: GenericArray<u8, U32>,
        ) -> (
            GenericArray<u8, U32>,
            GenericArray<u8, U32>,
            aead::Nonce<Self::Aead>,
        ) {
            let ck = Hmac::<Sha256>::new_from_slice(&ck)
                .unwrap()
                .chain_update([0x01])
                .finalize()
                .into_bytes();
            let mk = Hmac::<Sha256>::new_from_slice(&ck)
                .unwrap()
                .chain_update([0x02])
                .finalize()
                .into_bytes();
            let iv = Hmac::<Sha256>::new_from_slice(&ck)
                .unwrap()
                .chain_update([0x03])
                .finalize()
                .into_bytes();
            (ck, mk, iv.split().0)
        }
    }

    #[test]
    fn verify() {
        let mut rng = rand::thread_rng();

        let ask = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);

        let bsk = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let bpk = x25519_dalek::PublicKey::from(&bsk);

        let secret = ask.diffie_hellman(&bpk).to_bytes().into();

        let mut b = DoubleRatchetState::<Settings>::init1(
            secret,
            (bpk.to_bytes().into(), bsk.to_bytes().into()),
        );
        let mut a = DoubleRatchetState::<Settings>::init2(secret, bpk.to_bytes().into(), &mut rng);

        let (h1, m1) = a.encrypt(b"m1".to_vec(), b"a1".to_vec());
        assert_eq!(b.decrypt(h1, m1, b"a1".to_vec(), &mut rng).unwrap(), b"m1");

        let (h2, m2) = b.encrypt(b"m2".to_vec(), b"a2".to_vec());
        assert_eq!(a.decrypt(h2, m2, b"a2".to_vec(), &mut rng).unwrap(), b"m2");

        let (h3, m3) = a.encrypt(b"m3".to_vec(), b"a3".to_vec());
        let (h4, m4) = b.encrypt(b"m4".to_vec(), b"a4".to_vec());

        assert_eq!(b.decrypt(h3, m3, b"a3".to_vec(), &mut rng).unwrap(), b"m3");
        assert_eq!(a.decrypt(h4, m4, b"a4".to_vec(), &mut rng).unwrap(), b"m4");

        let (h5, m5) = a.encrypt(b"m5".to_vec(), b"a5".to_vec());
        let (h6, m6) = a.encrypt(b"m6".to_vec(), b"a6".to_vec());

        assert_eq!(b.decrypt(h5, m5, b"a5".to_vec(), &mut rng).unwrap(), b"m5");
        assert_eq!(b.decrypt(h6, m6, b"a6".to_vec(), &mut rng).unwrap(), b"m6");
    }
}
