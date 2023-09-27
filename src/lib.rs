use core::fmt;
use core::marker::PhantomData;
use core::ops::Add;
use std::ops::Sub;

use generic_array::{
    sequence::{Concat, Split},
    typenum::{U32, U64},
    ArrayLength, GenericArray,
};

pub struct SymmetricKeyRatchet<ChainKey: ArrayLength, MessageKey: ArrayLength, Kdf> {
    kdf: Kdf,
    keys: PhantomData<(ChainKey, MessageKey)>,
}

impl<ChainKey, MessageKey, K> SymmetricKeyRatchet<ChainKey, MessageKey, K>
where
    ChainKey: ArrayLength + Add<MessageKey>,
    MessageKey: ArrayLength,
    ChainKey::Output: ArrayLength + Sub<ChainKey, Output = MessageKey>,
    K: Kdf,
{
    pub fn ratchet(&mut self) -> GenericArray<u8, MessageKey> {
        let mut keys = <GenericArray<u8, ChainKey> as Concat<u8, MessageKey>>::concat(
            GenericArray::<u8, ChainKey>::default(),
            GenericArray::<u8, MessageKey>::default(),
        );
        self.kdf.expand(&[], &mut keys);
        let (chain, message) = Split::<u8, ChainKey>::split(keys);
        self.kdf = K::from_prk(&chain).unwrap();
        message
    }
}

pub trait Kdf: Sized {
    /// Initialise the KDF with the psuedo-random-key
    fn from_prk(prk: &[u8]) -> Result<Self, InvalidPrkLength>;

    /// Derive new keying material from the prk
    fn expand(&self, info: &[u8], output: &mut [u8]);
}

/// Error that is returned when supplied pseudorandom key (PRK) is not long enough.
#[derive(Copy, Clone, Debug)]
pub struct InvalidPrkLength;

impl fmt::Display for InvalidPrkLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("invalid pseudorandom key length, too short")
    }
}

// #[cfg(feature = "std")]
// #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl ::std::error::Error for InvalidPrkLength {}

pub struct DiffieHellmanRatchet<Dh: DiffieHellman, K: Kdf> {
    kdf: K,
    sk: Dh::SecretKey,
}

pub struct DhRatchetOutput<Dh: DiffieHellman> {
    pub new_public_key: Dh::PublicKey,
    pub recv_chain_key: GenericArray<u8, U32>,
    pub send_chain_key: GenericArray<u8, U32>,
}

impl<Dh: DiffieHellman, K: Kdf> DiffieHellmanRatchet<Dh, K> {
    pub fn ratchet(&mut self, pk: Dh::PublicKey) -> DhRatchetOutput<Dh> {
        let (new_public_key, new_secret_key) = Dh::keypair();
        let sk = core::mem::replace(&mut self.sk, new_secret_key.clone());

        let recv_info = Dh::exchange(pk.clone(), sk);
        let mut output = GenericArray::<u8, U64>::default();
        self.kdf.expand(&recv_info, &mut output);
        let (root_key, recv_chain_key): (GenericArray<u8, U32>, _) = output.split();
        self.kdf = K::from_prk(&root_key).unwrap();

        let send_info = Dh::exchange(pk, new_secret_key);
        let mut output = GenericArray::<u8, U64>::default();
        self.kdf.expand(&send_info, &mut output);
        let (root_key, send_chain_key): (GenericArray<u8, U32>, _) = output.split();
        self.kdf = K::from_prk(&root_key).unwrap();

        DhRatchetOutput {
            new_public_key,
            recv_chain_key,
            send_chain_key,
        }
    }
}

pub trait DiffieHellman {
    type PublicKey: Clone;
    type SecretKey: Clone;
    type OutputSize: ArrayLength;

    fn keypair() -> (Self::PublicKey, Self::SecretKey);
    fn exchange(pk: Self::PublicKey, sk: Self::SecretKey) -> GenericArray<u8, Self::OutputSize>;
}
