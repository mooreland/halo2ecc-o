use halo2_proofs::{
    arithmetic::CurveAffine,
    pairing::bn256::{Fq, Fr, G1Affine},
    plonk::Error,
};
use num_bigint::BigUint;

use crate::{
    assign::*, chips::native_chip::NativeChipOps as _, context::NativeScalarEccContext, utils::*,
};

use super::{bn256_constants::*, *};

impl<'a, C: CurveAffine> Fq2BnSpecificOps<C::Base, C::Scalar> for NativeScalarEccContext<'a, C> {
    fn fq2_mul_by_nonresidue(
        &mut self,
        a: &AssignedFq2<C::Base, C::Scalar>,
    ) -> Result<AssignedFq2<C::Base, C::Scalar>, Error> {
        let a2 = self.fq2_double(a)?;
        let a4 = self.fq2_double(&a2)?;
        let a8 = self.fq2_double(&a4)?;

        let t = self.integer_context().int_add(&a8.0, &a.0)?;
        let c0 = self.integer_context().int_sub(&t, &a.1)?;

        let t = self.integer_context().int_add(&a8.1, &a.0)?;
        let c1 = self.integer_context().int_add(&t, &a.1)?;

        Ok((c0, c1))
    }

    fn fq2_frobenius_map(
        &mut self,
        x: &AssignedFq2<C::Base, C::Scalar>,
        power: usize,
    ) -> Result<AssignedFq2<C::Base, C::Scalar>, Error> {
        let v =
            self.integer_context()
                .assign_int_constant(bn_to_field(&BigUint::from_bytes_le(
                    &FROBENIUS_COEFF_FQ2_C1[power % 2],
                )))?;
        Ok((x.0.clone(), self.integer_context().int_mul(&x.1, &v)?))
    }
}

impl<'a, C: CurveAffine> Fq6BnSpecificOps<C::Base, C::Scalar> for NativeScalarEccContext<'a, C> {
    fn fq6_mul_by_nonresidue(
        &mut self,
        a: &AssignedFq6<C::Base, C::Scalar>,
    ) -> Result<AssignedFq6<C::Base, C::Scalar>, Error> {
        Ok((self.fq2_mul_by_nonresidue(&a.2)?, a.0.clone(), a.1.clone()))
    }

    fn fq6_frobenius_map(
        &mut self,
        x: &AssignedFq6<C::Base, C::Scalar>,
        power: usize,
    ) -> Result<AssignedFq6<C::Base, C::Scalar>, Error> {
        let c0 = self.fq2_frobenius_map(&x.0, power)?;
        let c1 = self.fq2_frobenius_map(&x.1, power)?;
        let c2 = self.fq2_frobenius_map(&x.2, power)?;

        let coeff_c1 =
            FROBENIUS_COEFF_FQ6_C1[power % 6].map(|x| bn_to_field(&BigUint::from_bytes_le(&x)));
        let coeff_c1 = self.fq2_assign_constant((coeff_c1[0], coeff_c1[1]))?;
        let c1 = self.fq2_mul(&c1, &coeff_c1)?;
        let coeff_c2 =
            FROBENIUS_COEFF_FQ6_C2[power % 6].map(|x| bn_to_field(&BigUint::from_bytes_le(&x)));
        let coeff_c2 = self.fq2_assign_constant((coeff_c2[0], coeff_c2[1]))?;
        let c2 = self.fq2_mul(&c2, &coeff_c2)?;

        Ok((c0, c1, c2))
    }
}

impl<'a, C: CurveAffine> Fq12BnSpecificOps<C::Base, C::Scalar> for NativeScalarEccContext<'a, C> {
    fn fq12_frobenius_map(
        &mut self,
        x: &AssignedFq12<C::Base, C::Scalar>,
        power: usize,
    ) -> Result<AssignedFq12<C::Base, C::Scalar>, Error> {
        let c0 = self.fq6_frobenius_map(&x.0, power)?;
        let c1 = self.fq6_frobenius_map(&x.1, power)?;

        let coeff =
            FROBENIUS_COEFF_FQ12_C1[power % 12].map(|x| bn_to_field(&BigUint::from_bytes_le(&x)));
        let coeff = self.fq2_assign_constant((coeff[0], coeff[1]))?;
        let c1c0 = self.fq2_mul(&c1.0, &coeff)?;
        let c1c1 = self.fq2_mul(&c1.1, &coeff)?;
        let c1c2 = self.fq2_mul(&c1.2, &coeff)?;

        Ok((c0, (c1c0, c1c1, c1c2)))
    }
}

impl<'a> NativeScalarEccContext<'a, G1Affine> {
    fn prepare_g2(
        &mut self,
        g2: &AssignedG2Affine<G1Affine, Fr>,
    ) -> Result<AssignedG2Prepared<G1Affine, Fr>, Error> {
        let neg_g2 = self.g2_neg(&g2)?;

        let mut coeffs = vec![];
        let mut r = self.g2affine_to_g2(g2)?;

        for i in (1..SIX_U_PLUS_2_NAF.len()).rev() {
            coeffs.push(self.doubling_step(&mut r)?);
            let x = SIX_U_PLUS_2_NAF[i - 1];
            match x {
                1 => {
                    coeffs.push(self.addition_step(&mut r, &g2)?);
                }
                -1 => {
                    coeffs.push(self.addition_step(&mut r, &neg_g2)?);
                }
                _ => continue,
            }
        }

        let mut q1 = g2.clone();

        let c11 = self.fq2_assign_constant((
            bn_to_field(&BigUint::from_bytes_le(&FROBENIUS_COEFF_FQ6_C1[1][0])),
            bn_to_field(&BigUint::from_bytes_le(&FROBENIUS_COEFF_FQ6_C1[1][1])),
        ))?;
        let c12 = self.fq2_assign_constant((
            bn_to_field(&BigUint::from_bytes_le(&FROBENIUS_COEFF_FQ6_C1[2][0])),
            bn_to_field(&BigUint::from_bytes_le(&FROBENIUS_COEFF_FQ6_C1[2][1])),
        ))?;
        let xi = self.fq2_assign_constant((
            bn_to_field(&BigUint::from_bytes_le(&XI_TO_Q_MINUS_1_OVER_2[0])),
            bn_to_field(&BigUint::from_bytes_le(&XI_TO_Q_MINUS_1_OVER_2[1])),
        ))?;

        q1.x.1 = self.integer_context().int_neg(&q1.x.1)?;
        q1.x = self.fq2_mul(&q1.x, &c11)?;

        q1.y.1 = self.integer_context().int_neg(&q1.y.1)?;
        q1.y = self.fq2_mul(&q1.y, &xi)?;

        coeffs.push(self.addition_step(&mut r, &q1)?);

        let mut minusq2 = g2.clone();
        minusq2.x = self.fq2_mul(&minusq2.x, &c12)?;
        coeffs.push(self.addition_step(&mut r, &minusq2)?);

        Ok(AssignedG2Prepared::new(coeffs))
    }

    fn ell(
        &mut self,
        f: &AssignedFq12<Fq, Fr>,
        coeffs: &[AssignedFq2<Fq, Fr>; 3],
        p: &AssignedG1Affine<G1Affine, Fr>,
    ) -> Result<AssignedFq12<Fq, Fr>, Error> {
        let c00 = &coeffs[0].0;
        let c01 = &coeffs[0].1;
        let c10 = &coeffs[1].0;
        let c11 = &coeffs[1].1;

        let c00 = self.integer_context().int_mul(&c00, &p.y)?;
        let c01 = self.integer_context().int_mul(&c01, &p.y)?;
        let c10 = self.integer_context().int_mul(&c10, &p.x)?;
        let c11 = self.integer_context().int_mul(&c11, &p.x)?;

        self.fq12_mul_by_034(f, &(c00, c01), &(c10, c11), &coeffs[2])
    }

    // -y + alpha*x*w + bias*w^3 (alpha is slope, w is Fp12 =Fp2[w]/(w^2-u), Fp12 represents in Fp2)
    // coeffs:[alpha, bias] and exclude neg_one to save 1 circuit allocation
    fn ell_on_prove_pairing(
        &mut self,
        f: &AssignedFq12<Fq, Fr>,
        neg_one: &AssignedFq2<Fq, Fr>,
        coeffs: &[AssignedFq2<Fq, Fr>; 2],
        p: &AssignedG1Affine<G1Affine, Fr>,
    ) -> Result<AssignedFq12<Fq, Fr>, Error> {
        let c00 = &neg_one.0;
        let c01 = &neg_one.1;
        let c10 = &coeffs[0].0;
        let c11 = &coeffs[0].1;

        let c00 = self.integer_context().int_mul(&c00, &p.y)?;
        let c01 = self.integer_context().int_mul(&c01, &p.y)?;
        let c10 = self.integer_context().int_mul(&c10, &p.x)?;
        let c11 = self.integer_context().int_mul(&c11, &p.x)?;

        self.fq12_mul_by_034(f, &(c00, c01), &(c10, c11), &coeffs[1])
    }

    fn multi_miller_loop(
        &mut self,
        terms: &[(
            &AssignedG1Affine<G1Affine, Fr>,
            &AssignedG2Prepared<G1Affine, Fr>,
        )],
    ) -> Result<AssignedFq12<Fq, Fr>, Error> {
        let mut pairs = vec![];
        for &(p, q) in terms {
            // not support identity
            self.integer_context()
                .plonk_region_context
                .assert_false(&p.z)?;
            pairs.push((p, q.coeffs.iter()));
        }

        let mut f = self.fq12_assign_one()?;

        for i in (1..SIX_U_PLUS_2_NAF.len()).rev() {
            if i != SIX_U_PLUS_2_NAF.len() - 1 {
                f = self.fq12_square(&f)?;
            }
            for &mut (p, ref mut coeffs) in &mut pairs {
                f = self.ell(&f, coeffs.next().unwrap(), &p)?;
            }
            let x = SIX_U_PLUS_2_NAF[i - 1];
            match x {
                1 => {
                    for &mut (p, ref mut coeffs) in &mut pairs {
                        f = self.ell(&f, coeffs.next().unwrap(), &p)?;
                    }
                }
                -1 => {
                    for &mut (p, ref mut coeffs) in &mut pairs {
                        f = self.ell(&f, coeffs.next().unwrap(), &p)?;
                    }
                }
                _ => continue,
            }
        }

        for &mut (p, ref mut coeffs) in &mut pairs {
            f = self.ell(&f, coeffs.next().unwrap(), &p)?;
        }

        for &mut (p, ref mut coeffs) in &mut pairs {
            f = self.ell(&f, coeffs.next().unwrap(), &p)?;
        }

        for &mut (_p, ref mut coeffs) in &mut pairs {
            assert!(coeffs.next().is_none());
        }

        Ok(f)
    }

    // verify miller loop rst by supplied c&wi instead of final exponent
    // c: lamada-th residual root for miller loop rst f
    // wi: make sure f*wi be 3-th residual
    fn multi_miller_loop_c_wi(
        &mut self,
        c: &AssignedFq12<Fq, Fr>,
        wi: &AssignedFq12<Fq, Fr>,
        terms: &[(
            &AssignedG1Affine<G1Affine, Fr>,
            &AssignedG2Prepared<G1Affine, Fr>,
        )],
    ) -> Result<AssignedFq12<Fq, Fr>, Error> {
        let mut pairs = vec![];
        for &(p, q) in terms {
            // not support identity
            self.integer_context()
                .plonk_region_context
                .assert_false(&p.z)?;
            pairs.push((p, q.coeffs.iter()));
        }

        let c_inv = self.fq12_unsafe_invert(c)?;
        // f = c_inv
        let mut f = c_inv.clone();

        for i in (1..SIX_U_PLUS_2_NAF.len()).rev() {
            f = self.fq12_square(&f)?;

            let x = SIX_U_PLUS_2_NAF[i - 1];
            // Update c_inv
            // f = f * c_inv, if digit == 1
            // f = f * c, if digit == -1
            match x {
                1 => f = self.fq12_mul(&f, &c_inv)?,
                -1 => f = self.fq12_mul(&f, &c)?,
                _ => {}
            }

            for &mut (p, ref mut coeffs) in &mut pairs {
                f = self.ell(&f, coeffs.next().unwrap(), &p)?;
            }
            match x {
                1 => {
                    for &mut (p, ref mut coeffs) in &mut pairs {
                        f = self.ell(&f, coeffs.next().unwrap(), &p)?;
                    }
                }
                -1 => {
                    for &mut (p, ref mut coeffs) in &mut pairs {
                        f = self.ell(&f, coeffs.next().unwrap(), &p)?;
                    }
                }
                _ => continue,
            }
        }

        // Update c_inv^p^i part
        // f = f * c_inv^p * c^{p^2} * c_inv^{p^3}
        let c_inv_p = self.fq12_frobenius_map(&c_inv, 1)?;
        let c_inv_p3 = self.fq12_frobenius_map(&c_inv, 3)?;
        let c_p2 = self.fq12_frobenius_map(&c, 2)?;
        f = self.fq12_mul(&f, &c_inv_p)?;
        f = self.fq12_mul(&f, &c_p2)?;
        f = self.fq12_mul(&f, &c_inv_p3)?;

        // scale f
        // f = f * wi
        f = self.fq12_mul(&f, &wi)?;

        for &mut (p, ref mut coeffs) in &mut pairs {
            f = self.ell(&f, coeffs.next().unwrap(), &p)?;
        }

        for &mut (p, ref mut coeffs) in &mut pairs {
            f = self.ell(&f, coeffs.next().unwrap(), &p)?;
        }

        for &mut (_p, ref mut coeffs) in &mut pairs {
            assert!(coeffs.next().is_none());
        }

        Ok(f)
    }

    // compute miller loop in affine coordinates and verify by c&wi
    // not including verify for step by step's add/double point
    fn multi_miller_loop_on_prove_pairing(
        &mut self,
        c: &AssignedFq12<Fq, Fr>,
        wi: &AssignedFq12<Fq, Fr>,
        terms: &[(
            &AssignedG1Affine<G1Affine, Fr>,
            &AssignedG2OnProvePrepared<G1Affine, Fr>,
        )],
    ) -> Result<AssignedFq12<Fq, Fr>, Error> {
        let mut pairs = vec![];
        for &(p, q) in terms {
            // not support identity
            self.integer_context()
                .plonk_region_context
                .assert_false(&p.z)?;
            pairs.push((p, q.coeffs.iter()));
        }
        let one = self.fq2_assign_one()?;
        let neg_one = self.fq2_neg(&one)?;

        let c_inv = self.fq12_unsafe_invert(c)?;
        //f=c_inv
        let mut f = c_inv.clone();

        for i in (1..SIX_U_PLUS_2_NAF.len()).rev() {
            f = self.fq12_square(&f)?;

            let x = SIX_U_PLUS_2_NAF[i - 1];
            // Update c_inv
            // f = f * c_inv, if digit == 1
            // f = f * c, if digit == -1
            match x {
                1 => f = self.fq12_mul(&f, &c_inv)?,
                -1 => f = self.fq12_mul(&f, &c)?,
                _ => {}
            }

            for &mut (p, ref mut coeffs) in &mut pairs {
                let coeff = coeffs.next().unwrap();
                f = self.ell_on_prove_pairing(&f, &neg_one, coeff, &p)?;
            }
            match x {
                1 => {
                    for &mut (p, ref mut coeffs) in &mut pairs {
                        let coeff = coeffs.next().unwrap();
                        f = self.ell_on_prove_pairing(&f, &neg_one, coeff, &p)?;
                    }
                }
                -1 => {
                    for &mut (p, ref mut coeffs) in &mut pairs {
                        let coeff = coeffs.next().unwrap();
                        f = self.ell_on_prove_pairing(&f, &neg_one, coeff, &p)?;
                    }
                }
                _ => continue,
            }
        }

        // update c_inv^p^i part
        // f = f * c_inv^p * c^{p^2} * c_inv^{p^3}
        let c_inv_p = self.fq12_frobenius_map(&c_inv, 1)?;
        let c_inv_p3 = self.fq12_frobenius_map(&c_inv, 3)?;
        let c_p2 = self.fq12_frobenius_map(&c, 2)?;
        f = self.fq12_mul(&f, &c_inv_p)?;
        f = self.fq12_mul(&f, &c_p2)?;
        f = self.fq12_mul(&f, &c_inv_p3)?;

        // scale f
        // f = f * wi
        f = self.fq12_mul(&f, &wi)?;

        for &mut (p, ref mut coeffs) in &mut pairs {
            let coeff = coeffs.next().unwrap();
            f = self.ell_on_prove_pairing(&f, &neg_one, coeff, &p)?;
        }

        for &mut (p, ref mut coeffs) in &mut pairs {
            let coeff = coeffs.next().unwrap();
            f = self.ell_on_prove_pairing(&f, &neg_one, coeff, &p)?;
        }

        for &mut (_p, ref mut coeffs) in &mut pairs {
            assert!(coeffs.next().is_none());
        }

        Ok(f)
    }

    fn double_verify(
        &mut self,
        v: &[AssignedFq2<Fq, Fr>; 2],
        zero: &AssignedFq2<Fq, Fr>,
        two: &AssignedFq2<Fq, Fr>,
        three: &AssignedFq2<Fq, Fr>,
        r: &mut AssignedG2Affine<G1Affine, Fr>,
    ) -> Result<(), Error> {
        let alpha = &v[0];
        let bias = &v[1];
        // y - alpha * x - bias =0
        let alpha_x = self.fq2_mul(alpha, &r.x)?;
        let y_minus_alpha_x = self.fq2_sub(&r.y, &alpha_x)?;
        let rst = self.fq2_sub(&y_minus_alpha_x, bias)?;
        self.fq2_assert_equal(zero, &rst)?;

        // 3x^2 = alpha * 2y
        let y_mul_2 = self.fq2_mul(&r.y, two)?;
        let alpha_2y = self.fq2_mul(alpha, &y_mul_2)?;
        let x_square = self.fq2_square(&r.x)?;
        let x_square_3 = self.fq2_mul(three, &x_square)?;
        let rst = self.fq2_sub(&x_square_3, &alpha_2y)?;
        self.fq2_assert_equal(zero, &rst)?;

        // x3 = alpha^2 - 2x
        let alpha_square = self.fq2_square(alpha)?;
        let x_double = self.fq2_double(&r.x)?;
        let x3 = self.fq2_sub(&alpha_square, &x_double)?;

        // y3 = -alpha * x3 - bias
        let alpha_x3 = self.fq2_mul(alpha, &x3)?;
        let alpha_x3_bias = self.fq2_add(&alpha_x3, bias)?;
        let y3 = self.fq2_neg(&alpha_x3_bias)?;

        *r = AssignedG2Affine::new(
            x3,
            y3,
            self.integer_context()
                .plonk_region_context
                .assign_constant(Fr::zero())?
                .into(),
        );

        Ok(())
    }

    fn addition_verify(
        &mut self,
        v: &[AssignedFq2<Fq, Fr>; 2],
        zero: &AssignedFq2<Fq, Fr>,
        r: &mut AssignedG2Affine<G1Affine, Fr>,
        p: &AssignedG2Affine<G1Affine, Fr>,
    ) -> Result<(), Error> {
        let alpha = &v[0];
        let bias = &v[1];
        // y - alpha*x - bias =0
        let alpha_x = self.fq2_mul(alpha, &r.x)?;
        let y_minus_alpha_x = self.fq2_sub(&r.y, &alpha_x)?;
        let rst = self.fq2_sub(&y_minus_alpha_x, bias)?;
        self.fq2_assert_equal(zero, &rst)?;

        let alpha_x = self.fq2_mul(alpha, &p.x)?;
        let y_minus_alpha_x = self.fq2_sub(&p.y, &alpha_x)?;
        let rst = self.fq2_sub(&y_minus_alpha_x, bias)?;
        self.fq2_assert_equal(zero, &rst)?;

        //x3 = alpha^2-x1-x2
        let alpha_square = self.fq2_square(alpha)?;
        let alpha_square_x1 = self.fq2_sub(&alpha_square, &r.x)?;
        let x3 = self.fq2_sub(&alpha_square_x1, &p.x)?;

        //y3 = -alpha*x3 - bias
        let alpha_x3 = self.fq2_mul(alpha, &x3)?;
        let alpha_x3_bias = self.fq2_add(&alpha_x3, bias)?;
        let y3 = self.fq2_neg(&alpha_x3_bias)?;

        *r = AssignedG2Affine::new(
            x3,
            y3,
            self.integer_context()
                .plonk_region_context
                .assign_constant(Fr::zero())?
                .into(),
        );

        Ok(())
    }

    // In case of need double&addition verify
    #[allow(dead_code)]
    fn multi_miller_loop_on_prove_pairing_with_verify(
        &mut self,
        c: &AssignedFq12<Fq, Fr>,
        wi: &AssignedFq12<Fq, Fr>,
        terms: &[(
            &AssignedG1Affine<G1Affine, Fr>,
            &AssignedG2OnProvePrepared<G1Affine, Fr>,
        )],
    ) -> Result<AssignedFq12<Fq, Fr>, Error> {
        let mut pairs = vec![];
        for &(p, q) in terms {
            // not support identity
            self.integer_context()
                .plonk_region_context
                .assert_false(&p.z)?;
            pairs.push((p, q.coeffs.iter()));
        }

        let mut init_q = vec![];
        for (_, q) in terms {
            init_q.push(q.init_q.clone());
        }
        let mut neg_q = vec![];
        for (_, q) in terms {
            neg_q.push(self.g2_neg(&q.init_q)?);
        }

        let mut frebenius_q = vec![];
        for q in init_q.iter() {
            let mut q1 = q.clone();

            let c11 = self.fq2_assign_constant((
                bn_to_field(&BigUint::from_bytes_le(&FROBENIUS_COEFF_FQ6_C1[1][0])),
                bn_to_field(&BigUint::from_bytes_le(&FROBENIUS_COEFF_FQ6_C1[1][1])),
            ))?;
            let c12 = self.fq2_assign_constant((
                bn_to_field(&BigUint::from_bytes_le(&FROBENIUS_COEFF_FQ6_C1[2][0])),
                bn_to_field(&BigUint::from_bytes_le(&FROBENIUS_COEFF_FQ6_C1[2][1])),
            ))?;
            let xi = self.fq2_assign_constant((
                bn_to_field(&BigUint::from_bytes_le(&XI_TO_Q_MINUS_1_OVER_2[0])),
                bn_to_field(&BigUint::from_bytes_le(&XI_TO_Q_MINUS_1_OVER_2[1])),
            ))?;

            q1.x.1 = self.integer_context().int_neg(&q1.x.1)?;
            q1.x = self.fq2_mul(&q1.x, &c11)?;

            q1.y.1 = self.integer_context().int_neg(&q1.y.1)?;
            q1.y = self.fq2_mul(&q1.y, &xi)?;

            let mut minusq2 = q.clone();
            minusq2.x = self.fq2_mul(&minusq2.x, &c12)?;

            frebenius_q.push((q1, minusq2));
        }

        let zero = self.fq2_assign_zero()?;
        let one = self.fq2_assign_one()?;
        let neg_one = self.fq2_neg(&one)?;
        let two = self.fq2_double(&one)?;
        let three = self.fq2_add(&two, &one)?;

        let c_inv = self.fq12_unsafe_invert(c)?;

        // f = c_inv
        let mut f = c_inv.clone();

        let mut next_q = init_q.clone();

        for i in (1..SIX_U_PLUS_2_NAF.len()).rev() {
            f = self.fq12_square(&f)?;

            let x = SIX_U_PLUS_2_NAF[i - 1];
            // update c_inv
            // f = f * c_inv, if digit == 1
            // f = f * c, if digit == -1
            match x {
                1 => f = self.fq12_mul(&f, &c_inv)?,
                -1 => f = self.fq12_mul(&f, &c)?,
                _ => {}
            }

            for ((p, coeffs), q) in pairs.iter_mut().zip(next_q.iter_mut()) {
                let coeff = coeffs.next().unwrap();
                self.double_verify(coeff, &zero, &two, &three, q)?;
                f = self.ell_on_prove_pairing(&f, &neg_one, coeff, &p)?;
            }
            match x {
                1 => {
                    for ((&mut (p, ref mut coeffs), q), init_q) in
                        pairs.iter_mut().zip(next_q.iter_mut()).zip(init_q.iter())
                    {
                        let coeff = coeffs.next().unwrap();
                        self.addition_verify(coeff, &zero, q, init_q)?;
                        f = self.ell_on_prove_pairing(&f, &neg_one, coeff, &p)?;
                    }
                }
                -1 => {
                    for ((&mut (p, ref mut coeffs), q), neg_q) in
                        pairs.iter_mut().zip(next_q.iter_mut()).zip(neg_q.iter())
                    {
                        let coeff = coeffs.next().unwrap();
                        self.addition_verify(coeff, &zero, q, neg_q)?;
                        f = self.ell_on_prove_pairing(&f, &neg_one, coeff, &p)?;
                    }
                }
                _ => continue,
            }
        }

        // update c_inv^p^i part
        // f = f * c_inv^p * c^{p^2} * c_inv^{p^3}
        let c_inv_p = self.fq12_frobenius_map(&c_inv, 1)?;
        let c_inv_p3 = self.fq12_frobenius_map(&c_inv, 3)?;
        let c_p2 = self.fq12_frobenius_map(&c, 2)?;
        f = self.fq12_mul(&f, &c_inv_p)?;
        f = self.fq12_mul(&f, &c_p2)?;
        f = self.fq12_mul(&f, &c_inv_p3)?;

        // scale f
        // f = f * wi
        f = self.fq12_mul(&f, &wi)?;

        for ((&mut (p, ref mut coeffs), q), frobe_q) in pairs
            .iter_mut()
            .zip(next_q.iter_mut())
            .zip(frebenius_q.iter())
        {
            let coeff = coeffs.next().unwrap();
            self.addition_verify(coeff, &zero, q, &frobe_q.0)?;
            f = self.ell_on_prove_pairing(&f, &neg_one, coeff, &p)?;
        }

        for ((&mut (p, ref mut coeffs), q), frobe_q) in pairs
            .iter_mut()
            .zip(next_q.iter_mut())
            .zip(frebenius_q.iter())
        {
            let coeff = coeffs.next().unwrap();
            self.addition_verify(coeff, &zero, q, &frobe_q.1)?;
            f = self.ell_on_prove_pairing(&f, &neg_one, coeff, &p)?;
        }

        for &mut (_p, ref mut coeffs) in &mut pairs {
            assert!(coeffs.next().is_none());
        }

        Ok(f)
    }

    fn exp_by_x(&mut self, f: &AssignedFq12<Fq, Fr>) -> Result<AssignedFq12<Fq, Fr>, Error> {
        let x = BN_X;
        let mut res = self.fq12_assign_one()?;
        for i in (0..64).rev() {
            res = self.fq12_cyclotomic_square(&res)?;
            if ((x >> i) & 1) == 1 {
                res = self.fq12_mul(&res, &f)?;
            }
        }
        Ok(res)
    }

    fn final_exponentiation(
        &mut self,
        f: &AssignedFq12<Fq, Fr>,
    ) -> Result<AssignedFq12<Fq, Fr>, Error> {
        let f1 = self.fq12_conjugate(&f)?;
        let mut f2 = self.fq12_unsafe_invert(&f)?;

        let mut r = self.fq12_mul(&f1, &f2)?;
        f2 = r.clone();
        r = self.fq12_frobenius_map(&r, 2)?;
        r = self.fq12_mul(&r, &f2)?;

        let mut fp = r.clone();
        fp = self.fq12_frobenius_map(&fp, 1)?;

        let mut fp2 = r.clone();
        fp2 = self.fq12_frobenius_map(&fp2, 2)?;
        let mut fp3 = fp2.clone();
        fp3 = self.fq12_frobenius_map(&fp3, 1)?;

        let mut fu = r.clone();
        fu = self.exp_by_x(&fu)?;

        let mut fu2 = fu.clone();
        fu2 = self.exp_by_x(&fu2)?;

        let mut fu3 = fu2.clone();
        fu3 = self.exp_by_x(&fu3)?;

        let mut y3 = fu.clone();
        y3 = self.fq12_frobenius_map(&y3, 1)?;

        let mut fu2p = fu2.clone();
        fu2p = self.fq12_frobenius_map(&fu2p, 1)?;

        let mut fu3p = fu3.clone();
        fu3p = self.fq12_frobenius_map(&fu3p, 1)?;

        let mut y2 = fu2.clone();
        y2 = self.fq12_frobenius_map(&y2, 2)?;

        let mut y0 = fp;
        y0 = self.fq12_mul(&y0, &fp2)?;
        y0 = self.fq12_mul(&y0, &fp3)?;

        let mut y1 = r;
        y1 = self.fq12_conjugate(&y1)?;

        let mut y5 = fu2;
        y5 = self.fq12_conjugate(&y5)?;

        y3 = self.fq12_conjugate(&y3)?;

        let mut y4 = fu;
        y4 = self.fq12_mul(&y4, &fu2p)?;
        y4 = self.fq12_conjugate(&y4)?;

        let mut y6 = fu3;
        y6 = self.fq12_mul(&y6, &fu3p)?;
        y6 = self.fq12_conjugate(&y6)?;

        y6 = self.fq12_cyclotomic_square(&y6)?;
        y6 = self.fq12_mul(&y6, &y4)?;
        y6 = self.fq12_mul(&y6, &y5)?;

        let mut t1 = y3;
        t1 = self.fq12_mul(&t1, &y5)?;
        t1 = self.fq12_mul(&t1, &y6)?;

        y6 = self.fq12_mul(&y6, &y2)?;

        t1 = self.fq12_cyclotomic_square(&t1)?;
        t1 = self.fq12_mul(&t1, &y6)?;
        t1 = self.fq12_cyclotomic_square(&t1)?;

        let mut t0 = t1.clone();
        t0 = self.fq12_mul(&t0, &y1)?;

        t1 = self.fq12_mul(&t1, &y0)?;

        t0 = self.fq12_cyclotomic_square(&t0)?;
        t0 = self.fq12_mul(&t0, &t1)?;

        Ok(t0)
    }
}

impl<'a> PairingChipOps<'a, G1Affine, Fr> for NativeScalarEccContext<'a, G1Affine> {
    fn prepare_g2(
        &mut self,
        g2: &AssignedG2Affine<G1Affine, Fr>,
    ) -> Result<AssignedG2Prepared<G1Affine, Fr>, Error> {
        self.prepare_g2(g2)
    }

    fn multi_miller_loop(
        &mut self,
        terms: &[(
            &AssignedG1Affine<G1Affine, Fr>,
            &AssignedG2Prepared<G1Affine, Fr>,
        )],
    ) -> Result<AssignedFq12<<G1Affine as halo2_proofs::arithmetic::CurveAffine>::Base, Fr>, Error>
    {
        self.multi_miller_loop(terms)
    }

    fn final_exponentiation(
        &mut self,
        f: &AssignedFq12<<G1Affine as halo2_proofs::arithmetic::CurveAffine>::Base, Fr>,
    ) -> Result<AssignedFq12<<G1Affine as halo2_proofs::arithmetic::CurveAffine>::Base, Fr>, Error>
    {
        self.final_exponentiation(f)
    }
}

impl<'a> PairingChipOnProvePairingOps<'a, G1Affine, Fr> for NativeScalarEccContext<'a, G1Affine> {
    fn multi_miller_loop_c_wi(
        &mut self,
        c: &AssignedFq12<<G1Affine as halo2_proofs::arithmetic::CurveAffine>::Base, Fr>,
        wi: &AssignedFq12<<G1Affine as halo2_proofs::arithmetic::CurveAffine>::Base, Fr>,
        terms: &[(
            &AssignedG1Affine<G1Affine, Fr>,
            &AssignedG2Prepared<G1Affine, Fr>,
        )],
    ) -> Result<AssignedFq12<<G1Affine as halo2_proofs::arithmetic::CurveAffine>::Base, Fr>, Error>
    {
        self.multi_miller_loop_c_wi(c, wi, terms)
    }

    fn multi_miller_loop_on_prove_pairing(
        &mut self,
        c: &AssignedFq12<<G1Affine as halo2_proofs::arithmetic::CurveAffine>::Base, Fr>,
        wi: &AssignedFq12<<G1Affine as halo2_proofs::arithmetic::CurveAffine>::Base, Fr>,
        terms: &[(
            &AssignedG1Affine<G1Affine, Fr>,
            &AssignedG2OnProvePrepared<G1Affine, Fr>,
        )],
    ) -> Result<AssignedFq12<<G1Affine as halo2_proofs::arithmetic::CurveAffine>::Base, Fr>, Error>
    {
        self.multi_miller_loop_on_prove_pairing(c, wi, terms)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr as _;
    use std::sync::Arc;

    use super::*;
    use crate::chips::ecc_chip::EccChipBaseOps as _;
    use crate::context::ParallelClone as _;
    use crate::context::PlonkRegionContext;
    use crate::context::RangeRegionContext;
    use crate::int_mul_gate::IntMulGate;
    use crate::int_mul_gate::IntMulGateConfig;
    use crate::kvmap_gate::KVMapGate;
    use crate::kvmap_gate::KVMapGateConfig;
    use crate::plonk_gate::*;
    use crate::range_gate::RangeGate;
    use crate::range_gate::RangeGateConfig;
    use crate::range_info::RangeInfo;
    use crate::utils::test::*;
    use ark_std::One as _;
    use ark_std::{end_timer, start_timer};
    use floor_planner::FlatFloorPlanner;
    use halo2_proofs::arithmetic::BaseExt;
    use halo2_proofs::arithmetic::Field as _;
    use halo2_proofs::arithmetic::MillerLoopResult as _;
    use halo2_proofs::circuit::*;
    use halo2_proofs::pairing::bn256::*;
    use halo2_proofs::pairing::group::Curve;
    use halo2_proofs::pairing::group::Group as _;
    use halo2_proofs::plonk::*;
    use num_traits::Num as _;
    use num_traits::ToPrimitive as _;
    use rand_core::OsRng;
    use std::ops::Mul;
    use std::ops::Neg;

    #[derive(Clone, Debug)]
    struct TestCircuit<F: Clone + Fn(&mut NativeScalarEccContext<'_, G1Affine>) -> Result<(), Error>> {
        fill: F,
    }

    impl<F: Clone + Fn(&mut NativeScalarEccContext<'_, G1Affine>) -> Result<(), Error>> Circuit<Fr>
        for TestCircuit<F>
    {
        type Config = (
            PlonkGateConfig,
            RangeGateConfig,
            IntMulGateConfig,
            KVMapGateConfig,
        );
        type FloorPlanner = FlatFloorPlanner;

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let plonk_gate_config = PlonkGate::<Fr>::configure(meta);
            let range_gate_config = RangeGate::configure(meta);
            let int_mul_gate_config =
                IntMulGate::configure(meta, plonk_gate_config.var, &RangeInfo::<Fq, Fr>::new());
            let kvmap_gate_config =
                KVMapGate::configure(meta, plonk_gate_config.var[0..2].try_into().unwrap());
            (
                plonk_gate_config,
                range_gate_config,
                int_mul_gate_config,
                kvmap_gate_config,
            )
        }

        fn without_witnesses(&self) -> Self {
            self.clone()
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let timer = start_timer!(|| "synthesize");
            layouter.assign_region(
                || "test",
                |region| {
                    let plonk_region_context =
                        PlonkRegionContext::new_with_kvmap(&region, &config.0, &config.3);
                    let range_region_context = RangeRegionContext::new(&region, &config.1);
                    let mut native_ecc_context = NativeScalarEccContext::new(
                        plonk_region_context,
                        range_region_context,
                        &config.2,
                        Arc::new(RangeInfo::new()),
                    );

                    native_ecc_context
                        .integer_context
                        .range_region_context
                        .init()?;
                    (self.fill)(&mut native_ecc_context)?;

                    let timer = start_timer!(|| "finalize_int_mul");
                    native_ecc_context.integer_context.finalize_int_mul()?;
                    end_timer!(timer);

                    let timer = start_timer!(|| "finalize_compact_cells");
                    native_ecc_context
                        .integer_context
                        .range_region_context
                        .finalize_compact_cells()?;
                    end_timer!(timer);

                    Ok(())
                },
            )?;
            end_timer!(timer);
            Ok(())
        }
    }

    fn tonelli_shanks_cubic(a: Fq12, c: Fq12, s: u32, t: BigUint, k: BigUint) -> Fq12 {
        // let mut r = a.pow(t.to_u64_digits());
        let mut r = a.pow_vartime(t.to_u64_digits());
        let e = 3_u32.pow(s - 1);
        let exp = 3_u32.pow(s) * &t;

        // compute cubic root of (a^t)^-1, say h
        let (mut h, cc, mut c) = (
            Fq12::one(),
            // c.pow([e as u64]),
            c.pow_vartime([e as u64]),
            c.invert().unwrap(),
        );
        for i in 1..(s as i32) {
            let delta = (s as i32) - i - 1;
            let d = if delta < 0 {
                r.pow_vartime((&exp / 3_u32.pow((-delta) as u32)).to_u64_digits())
            } else {
                r.pow_vartime([3_u32.pow(delta as u32).to_u64().unwrap()])
            };
            if d == cc {
                (h, r) = (h * c, r * c.pow_vartime([3_u64]));
            } else if d == cc.pow_vartime([2_u64]) {
                (h, r) = (
                    h * c.pow_vartime([2_u64]),
                    r * c.pow_vartime([3_u64]).pow_vartime([2_u64]),
                );
            }
            c = c.pow_vartime([3_u64])
        }

        // recover cubic root of a
        r = a.pow_vartime(k.to_u64_digits()) * h;
        if t == 3_u32 * k + 1_u32 {
            r = r.invert().unwrap();
        }

        assert_eq!(r.pow_vartime([3_u64]), a);
        r
    }

    // refer from Algorithm 5 of "On Proving Pairings"(https://eprint.iacr.org/2024/640.pdf)
    fn compute_c_wi(f: Fq12) -> (Fq12, Fq12) {
        // let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        let p = BigUint::from_str(
            "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        )
        .unwrap();

        let r = BigUint::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .unwrap();
        let lambda = BigUint::from_str(
            "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
        ).unwrap();

        let s = 3_u32;
        let exp = p.pow(12_u32) - 1_u32;
        let h = &exp / &r;
        let t = &exp / 3_u32.pow(s);
        let k = (&t + 1_u32) / 3_u32;
        let m = &lambda / &r;
        let d = 3_u32;
        let mm = &m / d;

        // let mut prng = ChaCha20Rng::seed_from_u64(0);
        let cofactor_cubic = 3_u32.pow(s - 1) * &t;

        // make f is r-th residue, but it's not cubic residue
        assert_eq!(f.pow_vartime(h.to_u64_digits()), Fq12::one());
        //todo sometimes  f is cubic residue
        // assert_ne!(f.pow_vartime(cofactor_cubic.to_u64_digits()), Fq12::one());

        // sample a proper scalar w which is cubic non-residue
        let w = {
            let (mut w, mut z) = (Fq12::one(), Fq12::one());
            while w == Fq12::one() {
                // choose z which is 3-th non-residue
                let mut legendre = Fq12::one();
                while legendre == Fq12::one() {
                    z = Fq12::random(&mut OsRng);
                    legendre = z.pow_vartime(cofactor_cubic.to_u64_digits());
                }
                // obtain w which is t-th power of z
                w = z.pow_vartime(t.to_u64_digits());
            }
            w
        };

        // make sure 27-th root w, is 3-th non-residue and r-th residue
        assert_ne!(w.pow_vartime(cofactor_cubic.to_u64_digits()), Fq12::one());
        assert_eq!(w.pow_vartime(h.to_u64_digits()), Fq12::one());

        let wi = if f.pow_vartime(cofactor_cubic.to_u64_digits()) == Fq12::one() {
            Fq12::one()
        } else {
            // just two option, w and w^2, since w^3 must be cubic residue, leading f*w^3 must not be cubic residue
            let mut wi = w;
            if (f * wi).pow_vartime(cofactor_cubic.to_u64_digits()) != Fq12::one() {
                assert_eq!(
                    (f * w * w).pow_vartime(cofactor_cubic.to_u64_digits()),
                    Fq12::one()
                );
                wi = w * w;
            }
            wi
        };

        assert_eq!(wi.pow_vartime(h.to_u64_digits()), Fq12::one());

        assert_eq!(lambda, &d * &mm * &r);
        // f1 is scaled f
        let f1 = f * wi;

        // r-th root of f1, say f2
        let r_inv = r.modinv(&h).unwrap();
        assert_ne!(r_inv, BigUint::one());
        let f2 = f1.pow_vartime(r_inv.to_u64_digits());
        assert_ne!(f2, Fq12::one());

        // m'-th root of f, say f3
        let mm_inv = mm.modinv(&(r * h)).unwrap();
        assert_ne!(mm_inv, BigUint::one());
        let f3 = f2.pow_vartime(mm_inv.to_u64_digits());
        assert_eq!(f3.pow_vartime(cofactor_cubic.to_u64_digits()), Fq12::one());
        assert_ne!(f3, Fq12::one());

        // d-th (cubic) root, say c
        let c = tonelli_shanks_cubic(f3, w, s, t, k);
        assert_ne!(c, Fq12::one());
        assert_eq!(c.pow_vartime(lambda.to_u64_digits()), f * wi);

        (c, wi)
    }

    fn decode_fq12(
        a: &Fq12,
    ) -> (
        ((Fq, Fq), (Fq, Fq), (Fq, Fq)),
        ((Fq, Fq), (Fq, Fq), (Fq, Fq)),
    ) {
        return (
            (
                (a.c0.c0.c0, a.c0.c0.c1),
                (a.c0.c1.c0, a.c0.c1.c1),
                (a.c0.c2.c0, a.c0.c2.c1),
            ),
            (
                (a.c1.c0.c0, a.c1.c0.c1),
                (a.c1.c1.c0, a.c1.c1.c1),
                (a.c1.c2.c0, a.c1.c2.c1),
            ),
        );
    }

    fn fill_pairing_test(
        context: &mut NativeScalarEccContext<'_, G1Affine>,
        is_success: bool,
    ) -> Result<(), Error> {
        if is_success {
            // exp = 6x + 2 + p - p^2 = lambda - p^3
            let fq_module = Fq::MODULUS;
            let hex_str = fq_module
                .strip_prefix("0x")
                .or_else(|| fq_module.strip_prefix("0X"))
                .unwrap_or(fq_module);
            let p_pow3 = &BigUint::from_str_radix(hex_str, 16).unwrap().pow(3_u32);

            //0x1baaa710b0759ad331ec15183177faf68148fd2e5e487f1c2421c372dee2ddcdd45cf150c7e2d75ab87216b02105ec9bf0519bc6772f06e788e401a57040c54eb9b42c6f8f8e030b136a4fdd951c142faf174e7e839ac9157f83d3135ae0c55
            let lambda = BigUint::from_str(
        "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
    ).unwrap();

            let (exp, sign) = if lambda > *p_pow3 {
                (lambda - p_pow3, true)
            } else {
                (p_pow3 - lambda, false)
            };

            // prove e(P1, Q1) = e(P2, Q2)
            // namely e(-P1, Q1) * e(P2, Q2) = 1
            let p1 = G1::random(&mut OsRng);
            let q2 = G2::random(&mut OsRng);
            let factor = Fr::from_raw([3_u64, 0, 0, 0]);
            let p2 = p1.mul(&factor).to_affine();
            let q1 = q2.mul(&factor).to_affine();
            let q1_on_prove_prepared = G2OnProvePrepared::from(q1);
            let q2_on_prove_prepared = G2OnProvePrepared::from(q2.to_affine());

            let f = multi_miller_loop_on_prove_pairing_prepare(&[
                (&p1.neg().to_affine(), &q1_on_prove_prepared),
                (&p2, &q2_on_prove_prepared),
            ]);

            assert_eq!(Fq12::one(), f.final_exponentiation().0);
            let f = f.0;

            let (c, wi) = compute_c_wi(f);
            let c_inv = c.invert().unwrap();
            let hint = if sign {
                f * wi * (c_inv.pow_vartime(exp.to_u64_digits()))
            } else {
                f * wi * (c_inv.pow_vartime(exp.to_u64_digits()).invert().unwrap())
            };
            assert_eq!(hint, c.pow_vartime(p_pow3.to_u64_digits()));

            let c_assign = context.fq12_assign(Some(decode_fq12(&c)))?;
            let wi_assign = context.fq12_assign(Some(decode_fq12(&wi)))?;

            let mut coeffs_q1: Vec<[AssignedFq2<Fq, Fr>; 2]> = vec![];
            for v in get_g2_on_prove_prepared_coeffs(&q1_on_prove_prepared).iter() {
                coeffs_q1.push([
                    context.fq2_assign(Some((v.0 .0, v.0 .1)))?,
                    context.fq2_assign(Some((v.1 .0, v.1 .1)))?,
                ]);
            }
            let mut coeffs_q2: Vec<[AssignedFq2<Fq, Fr>; 2]> = vec![];
            for v in get_g2_on_prove_prepared_coeffs(&q2_on_prove_prepared).iter() {
                coeffs_q2.push([
                    context.fq2_assign(Some((v.0 .0, v.0 .1)))?,
                    context.fq2_assign(Some((v.1 .0, v.1 .1)))?,
                ]);
            }

            let p1_assign = context.assign_point(Some(-p1.to_affine()))?;
            let p2_assign = context.assign_point(Some(p2))?;

            let q1x = context.fq2_assign(Some((
                q1.coordinates().unwrap().x().c0,
                q1.coordinates().unwrap().x().c1,
            )))?;
            let q1y = context.fq2_assign(Some((
                q1.coordinates().unwrap().y().c0,
                q1.coordinates().unwrap().y().c1,
            )))?;
            let q1_assign = AssignedG2Affine::new(
                q1x,
                q1y,
                context
                    .get_plonk_region_context()
                    .assign_constant(Fr::zero())?
                    .into(),
            );

            let q2_affine = q2.to_affine();
            let q2x = context.fq2_assign(Some((
                q2_affine.coordinates().unwrap().x().c0,
                q2_affine.coordinates().unwrap().x().c1,
            )))?;
            let q2y = context.fq2_assign(Some((
                q2_affine.coordinates().unwrap().y().c0,
                q2_affine.coordinates().unwrap().y().c1,
            )))?;
            let q2_assign = AssignedG2Affine::new(
                q2x,
                q2y,
                context
                    .get_plonk_region_context()
                    .assign_constant(Fr::zero())?
                    .into(),
            );

            let q1_prepared = AssignedG2OnProvePrepared::new(coeffs_q1, q1_assign);
            let q2_prepared = AssignedG2OnProvePrepared::new(coeffs_q2, q2_assign);

            let timer = start_timer!(|| "setup");
            context.check_pairing_on_prove_pairing(
                &c_assign,
                &wi_assign,
                &[(&p1_assign, &q1_prepared), (&p2_assign, &q2_prepared)],
            )?;
            end_timer!(timer);

            println!("offset is {:?}", context.offset());
        } else {
            unimplemented!()
        }
        Ok(())
    }

    #[test]
    fn test_bn256_pairing_chip_success() {
        run_circuit_on_bn256(
            TestCircuit {
                fill: |context| {
                    let is_success = true;

                    for v in [fill_pairing_test] {
                        v(context, is_success)?;
                    }

                    Ok(())
                },
            },
            22,
        );
    }

    #[test]
    #[cfg(feature = "profile")]
    fn bench_bn256_pairing_chip_success() {
        bench_circuit_on_bn256(
            TestCircuit {
                fill: |context| {
                    let is_success = true;

                    for v in [fill_pairing_test] {
                        v(context, is_success)?;
                    }

                    Ok(())
                },
            },
            22,
        );
    }
}
