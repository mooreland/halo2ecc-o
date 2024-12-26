use halo2_proofs::{arithmetic::BaseExt, dev::MockProver, pairing::bn256::Fr, plonk::*};
use num_bigint::BigUint;
use num_traits::Num;

lazy_static! {
    pub static ref BN254_MODULUS: BigUint =
        BigUint::from_str_radix(Fr::MODULUS.strip_prefix("0x").unwrap(), 16).unwrap();
}

fn get_modulus_bn<F: BaseExt>() -> BigUint {
    if F::MODULUS == Fr::MODULUS {
        BN254_MODULUS.clone()
    } else {
        field_to_bn(&-F::one()) + 1u64
    }
}

pub fn field_to_bn<F: BaseExt>(f: &F) -> BigUint {
    let mut bytes: Vec<u8> = Vec::with_capacity(32);
    f.write(&mut bytes).unwrap();
    BigUint::from_bytes_le(&bytes[..])
}

pub fn bn_to_field<F: BaseExt>(bn: &BigUint) -> F {
    let modulus = get_modulus_bn::<F>();
    assert!(bn < &modulus);

    let mut bytes = bn.to_bytes_le();
    bytes.resize((modulus.bits() as usize + 7) / 8, 0);
    let mut bytes = &bytes[..];
    F::read(&mut bytes).unwrap()
}

pub(crate) trait ToField<F: BaseExt> {
    fn to_field(&self) -> F;
}

impl<F: BaseExt> ToField<F> for BigUint {
    fn to_field(&self) -> F {
        bn_to_field::<F>(self)
    }
}

impl<'a, F: BaseExt> ToField<F> for &'a BigUint {
    fn to_field(&self) -> F {
        bn_to_field::<F>(self)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use ark_std::{end_timer, start_timer};
    use halo2_proofs::{
        arithmetic::BaseExt,
        dev::MockProver,
        pairing::bn256::{Bn256, Fr, G1Affine},
        poly::commitment::{Params, ParamsVerifier},
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    };

    #[test]
    fn test_bn_conversion() {
        let timer = start_timer!(|| "test_bn_conversion");
        let f = Fr::rand();
        for _ in 0..1000000 {
            let bn = field_to_bn(&f);
            assert_eq!(f, bn_to_field(&bn));
        }
        end_timer!(timer);
    }

    pub(crate) fn bench_circuit_on_bn256<C: Circuit<Fr>>(circuit: C, k: u32) {
        use std::sync::Arc;
        use zkwasm_prover::{create_proof_from_advices_with_shplonk, prepare_advice_buffer};

        let timer = start_timer!(|| format!("build params with K = {}", k));
        let params: Params<G1Affine> = Params::<G1Affine>::unsafe_setup::<Bn256>(k);
        end_timer!(timer);

        let timer = start_timer!(|| "build vk");
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        end_timer!(timer);

        let vk_for_verify = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");

        let timer = start_timer!(|| "build pk");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
        end_timer!(timer);

        let timer = start_timer!(|| "create proof round 1");
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        let advices = {
            let mut advices = Arc::new(prepare_advice_buffer(&pk, false));

            generate_advice_from_synthesize(
                &params,
                &pk,
                &circuit,
                &[],
                &Arc::get_mut(&mut advices)
                    .unwrap()
                    .iter_mut()
                    .map(|x| (&mut x[..]) as *mut [_])
                    .collect::<Vec<_>>()[..],
            );

            advices
        };
        create_proof_from_advices_with_shplonk(&params, &pk, &[], advices, &mut transcript)
            .expect("proof generation should not fail");
        let _ = transcript.finalize();
        end_timer!(timer);

        let timer = start_timer!(|| "create proof round 2");
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        let advices = {
            let mut advices = Arc::new(prepare_advice_buffer(&pk, false));

            generate_advice_from_synthesize(
                &params,
                &pk,
                &circuit,
                &[],
                &Arc::get_mut(&mut advices)
                    .unwrap()
                    .iter_mut()
                    .map(|x| (&mut x[..]) as *mut [_])
                    .collect::<Vec<_>>()[..],
            );

            advices
        };
        create_proof_from_advices_with_shplonk(&params, &pk, &[], advices, &mut transcript)
            .expect("proof generation should not fail");
        let proof = transcript.finalize();
        end_timer!(timer);

        let params_verifier: ParamsVerifier<Bn256> = params.verifier(0).unwrap();

        let strategy = SingleVerifier::new(&params_verifier);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        let timer = start_timer!(|| "verify proof");
        verify_proof_with_shplonk(
            &params_verifier,
            &vk_for_verify,
            strategy,
            &[&[]],
            &mut transcript,
        )
        .unwrap();
        end_timer!(timer);
    }

    pub(crate) fn run_circuit_on_bn256<C: Circuit<Fr>>(circuit: C, k: u32) {
        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    pub(crate) fn run_circuit_on_bn256_expect_fail<C: Circuit<Fr>>(circuit: C, k: u32) {
        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert!(prover.verify().is_err());
    }
}
