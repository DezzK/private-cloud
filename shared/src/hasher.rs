use digest::generic_array::GenericArray;
use digest::typenum::U64;
use digest::{FixedOutput, HashMarker, Reset, Update};

#[derive(Debug, Clone)]
pub struct Hasher {
    hasher: blake3::Hasher,
}

impl HashMarker for Hasher {}

impl Default for Hasher {
    fn default() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }
}

impl Update for Hasher {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
}

impl Reset for Hasher {
    #[inline]
    fn reset(&mut self) {
        self.hasher.reset();
    }
}

impl digest::OutputSizeUser for Hasher {
    type OutputSize = U64;
}

impl FixedOutput for Hasher {
    #[inline]
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        self.hasher.finalize_xof().fill(out);
    }
}
