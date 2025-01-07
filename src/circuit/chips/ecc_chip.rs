use halo2_proofs::{
    arithmetic::{Coordinates, CurveAffine, Field, FieldExt},
    plonk::Error,
};
use num_bigint::BigUint;

use crate::{
    assign::{
        AssignedCondition, AssignedCurvature, AssignedInteger, AssignedNonZeroPoint, AssignedPoint,
        AssignedValue,
    },
    context::{IntegerContext, NativeEccContext, PlonkRegionContext},
    util::{bn_to_field, field_to_bn},
};

use super::{bit_chip::BitChipOps as _, int_chip::IntUnsafeError, native_chip::NativeChipOps as _};

#[derive(Debug)]
pub enum EccUnsafeError {
    AddSameOrNegPoint,
    AddIdentity,
    AssignIdentity,
    PlonkError(Error),
}

impl From<Error> for EccUnsafeError {
    fn from(value: Error) -> Self {
        EccUnsafeError::PlonkError(value)
    }
}

impl<'b, C: CurveAffine> EccChipBaseOps<'b, C, C::Scalar> for NativeEccContext<'b, C> {
    fn integer_context<'a>(
        &'a mut self,
    ) -> &'a mut IntegerContext<'b, <C as CurveAffine>::Base, C::Scalar> {
        &mut self.integer_context
    }

    fn plonk_region_context<'a>(&'a mut self) -> &'a mut PlonkRegionContext<'b, C::Scalar> {
        self.get_plonk_region_context()
    }
}

pub trait EccChipBaseOps<'b, C: CurveAffine, N: FieldExt> {
    fn integer_context<'a>(&'a mut self) -> &'a mut IntegerContext<'b, C::Base, N>;
    fn plonk_region_context<'a>(&'a mut self) -> &'a mut PlonkRegionContext<'b, N>;

    fn assign_constant_point(&mut self, c: C) -> Result<AssignedPoint<C, N>, Error> {
        let coordinates: Option<Coordinates<_>> = c.coordinates().into();
        let t: Option<_> = coordinates.map(|v| (v.x().clone(), v.y().clone())).into();
        let (x, y) = t.unwrap_or((C::Base::zero(), C::Base::zero()));
        let z = if c.is_identity().into() {
            N::one()
        } else {
            N::zero()
        };

        let x = self.integer_context().assign_int_constant(x)?;
        let y = self.integer_context().assign_int_constant(y)?;
        let z = self.plonk_region_context().assign_constant(z)?;

        Ok(AssignedPoint::new(x, y, z.into()))
    }

    fn assign_point(&mut self, c: Option<C>) -> Result<AssignedPoint<C, N>, Error> {
        let z = (|| {
            Some(if c?.is_identity().into() {
                N::one()
            } else {
                N::zero()
            })
        })();

        // For identity, assign (x, y) as generator to pass y^2 = x^3 + b, it is safe because of z bit.
        let coordinates = (|| {
            Some(if c?.is_identity().into() {
                C::generator().coordinates().unwrap()
            } else {
                c?.coordinates().unwrap()
            })
        })();
        let (x, y) = coordinates
            .map(|v| ((field_to_bn(v.x()), field_to_bn(v.y()))))
            .unzip();

        let x = self.integer_context().assign_w(x)?;
        let y = self.integer_context().assign_w(y)?;
        let z = self.plonk_region_context().assign_bit_opt(z)?;

        // Constrain y^2 = x^3 + b
        let b = self.integer_context().assign_int_constant(C::b())?;
        let y2 = self.integer_context().int_square(&y)?;
        let x2 = self.integer_context().int_square(&x)?;
        let x3 = self.integer_context().int_mul(&x2, &x)?;
        let right = self.integer_context().int_add(&x3, &b)?;
        self.integer_context().assert_int_equal(&y2, &right)?;

        let p = AssignedPoint::new(x, y, z);
        self.ecc_reduce(&p)
    }

    fn assign_non_zero_point(&mut self, c: Option<C>) -> Result<AssignedNonZeroPoint<C, N>, Error> {
        // For identity, assign (x, y) as generator to pass y^2 = x^3 + b, it is safe because of z bit.
        let coordinates = (|| {
            Some(if c?.is_identity().into() {
                unreachable!()
            } else {
                c?.coordinates().unwrap()
            })
        })();
        let (x, y) = coordinates
            .map(|v| ((field_to_bn(v.x()), field_to_bn(v.y()))))
            .unzip();

        let x = self.integer_context().assign_w(x)?;
        let y = self.integer_context().assign_w(y)?;

        // Constrain y^2 = x^3 + b
        let b = self.integer_context().assign_int_constant(C::b())?;
        let y2 = self.integer_context().int_square(&y)?;
        let x2 = self.integer_context().int_square(&x)?;
        let x3 = self.integer_context().int_mul(&x2, &x)?;
        let right = self.integer_context().int_add(&x3, &b)?;
        self.integer_context().assert_int_equal(&y2, &right)?;

        Ok(AssignedNonZeroPoint::new(x, y))
    }

    fn bisec_point(
        &mut self,
        cond: &AssignedCondition<N>,
        a: &AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let x = self.integer_context().bisec_int(cond, &a.x, &b.x)?;
        let y = self.integer_context().bisec_int(cond, &a.y, &b.y)?;
        let z = self.plonk_region_context().bisec_cond(cond, &a.z, &b.z)?;

        Ok(AssignedPoint::new(x, y, z))
    }

    fn lambda_to_point(
        &mut self,
        lambda: &AssignedCurvature<C, N>,
        a: &AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let l = &lambda.0;

        // cx = lambda ^ 2 - a.x - b.x
        let cx = {
            let l_square = self.integer_context().int_square(l)?;
            let t = self.integer_context().int_sub(&l_square, &a.x)?;
            let t = self.integer_context().int_sub(&t, &b.x)?;
            t
        };

        let cy = {
            let t = self.integer_context().int_sub(&a.x, &cx)?;
            let t = self.integer_context().int_mul(&t, l)?;
            let t = self.integer_context().int_sub(&t, &a.y)?;
            t
        };

        Ok(AssignedPoint::new(cx, cy, lambda.1))
    }

    fn get_curvature(&mut self, a: &AssignedPoint<C, N>) -> Result<AssignedCurvature<C, N>, Error> {
        // 3 * x ^ 2 / 2 * y
        let x_square = self.integer_context().int_square(&a.x)?;
        let numerator = self
            .integer_context()
            .int_mul_small_constant(&x_square, 3)?;
        let denominator = self.integer_context().int_mul_small_constant(&a.y, 2)?;

        let (z, v) = self.integer_context().int_div(&numerator, &denominator)?;
        Ok(AssignedCurvature(v, z))
    }

    fn bisec_curvature(
        &mut self,
        cond: &AssignedCondition<N>,
        a: &AssignedCurvature<C, N>,
        b: &AssignedCurvature<C, N>,
    ) -> Result<AssignedCurvature<C, N>, Error> {
        let v = self.integer_context().bisec_int(cond, &a.0, &b.0)?;
        let z = self.plonk_region_context().bisec_cond(cond, &a.1, &b.1)?;

        Ok(AssignedCurvature(v, z))
    }

    fn ecc_add(
        &mut self,
        a: &AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let diff_x = self.integer_context().int_sub(&a.x, &b.x)?;
        let diff_y = self.integer_context().int_sub(&a.y, &b.y)?;
        let (x_eq, tangent) = self.integer_context().int_div(&diff_y, &diff_x)?;

        let y_eq = self.integer_context().is_int_zero(&diff_y)?;
        let eq = self.plonk_region_context().and(&x_eq, &y_eq)?;

        let tangent = AssignedCurvature(tangent, x_eq);
        let a_curvature = self.get_curvature(a)?;
        let lambda = self.bisec_curvature(&eq, &a_curvature, &tangent)?;

        let p = self.lambda_to_point(&lambda, a, b)?;
        let p = self.bisec_point(&a.z, b, &p)?;
        let p = self.bisec_point(&b.z, a, &p)?;

        Ok(p)
    }

    fn ecc_double(&mut self, a: &AssignedPoint<C, N>) -> Result<AssignedPoint<C, N>, Error> {
        // Ensure scalar is odd, so double-a can't be identity if a is not identity.
        // assert!(!(field_to_bn(&-C::ScalarExt::one()).bit(0)));

        let a_curvature = self.get_curvature(a)?;
        let mut p = self.lambda_to_point(&a_curvature, &a, &a)?;
        p.z = self.plonk_region_context().or(&a.z, &p.z)?;

        Ok(p)
    }

    fn ecc_assert_equal(
        &mut self,
        a: &AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> Result<(), Error> {
        let eq_x = self.integer_context().is_int_equal(&a.x, &b.x)?;
        let eq_y = self.integer_context().is_int_equal(&a.y, &b.y)?;
        let eq_z = self.plonk_region_context().xnor(&a.z, &b.z)?;
        let eq_xy = self.plonk_region_context().and(&eq_x, &eq_y)?;
        let eq_xyz = self.plonk_region_context().and(&eq_xy, &eq_z)?;

        let is_both_identity = self.plonk_region_context().and(&a.z, &b.z)?;
        let eq = self.plonk_region_context().or(&eq_xyz, &is_both_identity)?;

        self.plonk_region_context().assert_true(&eq)?;
        Ok(())
    }

    fn ecc_neg(&mut self, a: &AssignedPoint<C, N>) -> Result<AssignedPoint<C, N>, Error> {
        let x = a.x.clone();
        let y = self.integer_context().int_neg(&a.y)?;
        let z = a.z.clone();

        Ok(AssignedPoint::new(x, y, z))
    }

    fn assign_identity(&mut self) -> Result<AssignedPoint<C, N>, Error> {
        let zero = self
            .integer_context()
            .assign_int_constant(C::Base::zero())?;
        let one = self.plonk_region_context().assign_constant(N::one())?;

        Ok(AssignedPoint::new(zero.clone(), zero.clone(), one.into()))
    }

    fn ecc_reduce(&mut self, a: &AssignedPoint<C, N>) -> Result<AssignedPoint<C, N>, Error> {
        let x = self.integer_context().reduce(&a.x)?;
        let y = self.integer_context().reduce(&a.y)?;
        let z = a.z;

        let identity = self.assign_identity()?;
        self.bisec_point(&z, &identity, &AssignedPoint::new(x, y, z))
    }

    fn ecc_encode(&mut self, p: &AssignedPoint<C, N>) -> Result<Vec<AssignedValue<N>>, Error> {
        assert!(p.x.limbs_le.len() == 3);

        let p = self.ecc_reduce(&p)?;
        let shift = bn_to_field(&(BigUint::from(1u64) << self.integer_context().info().limb_bits));
        let s0 = self.plonk_region_context().sum_with_constant(
            &[
                (&p.x.limbs_le[0].unwrap(), N::one()),
                (&p.x.limbs_le[1].unwrap(), shift),
            ],
            None,
        )?;
        let s1 = self.plonk_region_context().sum_with_constant(
            &[
                (&p.x.limbs_le[2].unwrap(), N::one()),
                (&p.y.limbs_le[0].unwrap(), shift),
            ],
            None,
        )?;
        let s2 = self.plonk_region_context().sum_with_constant(
            &[
                (&p.y.limbs_le[1].unwrap(), N::one()),
                (&p.y.limbs_le[2].unwrap(), shift),
            ],
            None,
        )?;
        Ok(vec![s0, s1, s2])
    }

    fn lambda_to_point_non_zero(
        &mut self,
        lambda: &AssignedInteger<C::Base, N>,
        a: &AssignedNonZeroPoint<C, N>,
        b: &AssignedNonZeroPoint<C, N>,
    ) -> Result<AssignedNonZeroPoint<C, N>, Error> {
        let l = lambda;

        // cx = lambda ^ 2 - a.x - b.x
        let cx = {
            let l_square = self.integer_context().int_square(l)?;
            let t = self.integer_context().int_sub(&l_square, &a.x)?;
            let t = self.integer_context().int_sub(&t, &b.x)?;
            t
        };

        let cy = {
            let t = self.integer_context().int_sub(&a.x, &cx)?;
            let t = self.integer_context().int_mul(&t, l)?;
            let t = self.integer_context().int_sub(&t, &a.y)?;
            t
        };

        Ok(AssignedNonZeroPoint::new(cx, cy))
    }

    fn ecc_add_unsafe(
        &mut self,
        a: &AssignedNonZeroPoint<C, N>,
        b: &AssignedNonZeroPoint<C, N>,
    ) -> Result<AssignedNonZeroPoint<C, N>, EccUnsafeError> {
        let diff_x = self.integer_context().int_sub(&a.x, &b.x)?;
        let diff_y = self.integer_context().int_sub(&a.y, &b.y)?;
        let tangent = self
            .integer_context()
            .int_div_unsafe(&diff_y, &diff_x)
            .map_err(|e| match e {
                IntUnsafeError::DivZero => EccUnsafeError::AddSameOrNegPoint,
                IntUnsafeError::PlonkError(error) => EccUnsafeError::PlonkError(error),
            })?;
        let res = self.lambda_to_point_non_zero(&tangent, a, b)?;

        Ok(res)
    }

    fn ecc_double_unsafe(
        &mut self,
        a: &AssignedNonZeroPoint<C, N>,
    ) -> Result<AssignedNonZeroPoint<C, N>, EccUnsafeError> {
        // 3 * x ^ 2 / 2 * y
        let x_square = self.integer_context().int_square(&a.x)?;
        let numerator = self
            .integer_context()
            .int_mul_small_constant(&x_square, 3)?;
        let denominator = self.integer_context().int_mul_small_constant(&a.y, 2)?;

        let curvature = self
            .integer_context()
            .int_div_unsafe(&numerator, &denominator)
            .map_err(|e| match e {
                IntUnsafeError::DivZero => EccUnsafeError::AddIdentity,
                IntUnsafeError::PlonkError(error) => EccUnsafeError::PlonkError(error),
            })?;

        let res = self.lambda_to_point_non_zero(&curvature, &a, &a)?;

        Ok(res)
    }

    fn ecc_neg_non_zero(
        &mut self,
        a: &AssignedNonZeroPoint<C, N>,
    ) -> Result<AssignedNonZeroPoint<C, N>, Error> {
        let x = a.x.clone();
        let y = self.integer_context().int_neg(&a.y)?;

        Ok(AssignedNonZeroPoint::new(x, y))
    }

    fn ecc_reduce_non_zero(
        &mut self,
        a: &AssignedNonZeroPoint<C, N>,
    ) -> Result<AssignedNonZeroPoint<C, N>, Error> {
        let x = self.integer_context().reduce(&a.x)?;
        let y = self.integer_context().reduce(&a.y)?;

        Ok(AssignedNonZeroPoint::new(x, y))
    }

    fn ecc_assert_equal_non_zero(
        &mut self,
        a: &AssignedNonZeroPoint<C, N>,
        b: &AssignedNonZeroPoint<C, N>,
    ) -> Result<(), Error> {
        self.integer_context().assert_int_equal(&a.x, &b.x)?;
        self.integer_context().assert_int_equal(&a.y, &b.y)?;
        Ok(())
    }

    fn ecc_non_zero_point_downgrade(
        &mut self,
        a: &AssignedNonZeroPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let zero = self.plonk_region_context().assign_constant(N::zero())?;
        Ok(AssignedPoint::new(a.x.clone(), a.y.clone(), zero.into()))
    }

    fn ecc_bisec_to_non_zero_point(
        &mut self,
        a: &AssignedPoint<C, N>,
        b: &AssignedNonZeroPoint<C, N>,
    ) -> Result<AssignedNonZeroPoint<C, N>, Error> {
        let x = self.integer_context().bisec_int(&a.z, &b.x, &a.x)?;
        let y = self.integer_context().bisec_int(&a.z, &b.y, &a.y)?;

        Ok(AssignedNonZeroPoint::new(x, y))
    }

    fn kvmap_set_ecc_non_zero(
        &mut self,
        gid: u64,
        k: &AssignedValue<N>,
        v: &AssignedNonZeroPoint<C, N>,
    ) -> Result<(), Error> {
        let gid = gid * 2;

        self.integer_context().kvmap_set_int(gid, k, &v.x)?;
        self.integer_context().kvmap_set_int(gid + 1, k, &v.y)?;

        Ok(())
    }

    fn kvmap_get_ecc_non_zero(
        &mut self,
        gid: u64,
        k: &AssignedValue<N>,
        v: &AssignedNonZeroPoint<C, N>,
    ) -> Result<AssignedNonZeroPoint<C, N>, Error> {
        let gid = gid * 2;

        let x = self.integer_context().kvmap_get_int(gid + 0, k, &v.x)?;
        let y = self.integer_context().kvmap_get_int(gid + 1, k, &v.y)?;

        Ok(AssignedNonZeroPoint::new(x, y))
    }

    fn pick_candidate_non_zero(
        &mut self,
        candidates: &Vec<AssignedNonZeroPoint<C, N>>,
        group_bits: &Vec<AssignedCondition<N>>,
    ) -> Result<(AssignedValue<N>, AssignedNonZeroPoint<C, N>), Error> {
        let curr_candidates: Vec<_> = candidates.clone();
        let index_vec = group_bits
            .iter()
            .enumerate()
            .map(|(i, x)| (x.as_ref(), N::from(1u64 << i)))
            .collect::<Vec<_>>();

        let index = self
            .plonk_region_context()
            .sum_with_constant(&index_vec[..], None)?;

        // Set index to 0 on setup
        let index_i = (index.value().unwrap_or(N::zero()).to_repr().as_ref())[0] as usize;

        let ci = &curr_candidates[index_i];
        Ok((index, ci.clone()))
    }
}
