use ml_dsa::{EncodedVerifyingKey, Signature, Verifier, VerifyingKey};
use pki_types::alg_id;
use pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};

macro_rules! verifier {
    ($name:ident, $algorithm:ident, $parameters:ty) => {
        #[derive(Debug)]
        pub(super) struct $name;

        impl SignatureVerificationAlgorithm for $name {
            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::$algorithm
            }

            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::$algorithm
            }

            fn verify_signature(
                &self,
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), InvalidSignature> {
                let encoded = EncodedVerifyingKey::<$parameters>::try_from(public_key)
                    .map_err(|_| InvalidSignature)?;
                let key = VerifyingKey::<$parameters>::decode(&encoded);
                let signature =
                    Signature::<$parameters>::try_from(signature).map_err(|_| InvalidSignature)?;
                key.verify(message, &signature)
                    .map_err(|_| InvalidSignature)
            }
        }
    };
}

verifier!(MlDsa44, ML_DSA_44, ml_dsa::MlDsa44);
verifier!(MlDsa65, ML_DSA_65, ml_dsa::MlDsa65);
verifier!(MlDsa87, ML_DSA_87, ml_dsa::MlDsa87);

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{Keypair, MlDsaParams, Signer, SigningKey};

    fn checks_signature<P: MlDsaParams>(verifier: &dyn SignatureVerificationAlgorithm) {
        let key = SigningKey::<P>::from_seed(&[42; 32].into());
        let public_key = key.verifying_key().encode();
        let message = b"TLS CertificateVerify";
        let mut signature = key.sign(message).encode();

        assert!(
            verifier
                .verify_signature(&public_key, message, &signature)
                .is_ok()
        );
        signature[0] ^= 1;
        assert!(
            verifier
                .verify_signature(&public_key, message, &signature)
                .is_err()
        );
    }

    #[test]
    fn verifies_all_tls_mldsa_schemes_and_rejects_tampering() {
        checks_signature::<ml_dsa::MlDsa44>(&MlDsa44);
        checks_signature::<ml_dsa::MlDsa65>(&MlDsa65);
        checks_signature::<ml_dsa::MlDsa87>(&MlDsa87);
    }
}
