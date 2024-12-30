use halo2_proofs::{
    arithmetic::{BaseExt, FieldExt},
    plonk::Error,
};
use num_bigint::BigUint;
use num_integer::Integer;

use crate::{
    assign::{AssignedInteger, AssignedValue, MAX_LIMBS},
    chips::native_chip::NativeChipOps,
    context::IntegerContext,
    pair,
    range_gate::COMPACT_BITS,
    range_info::RangeInfo,
    util::{bn_to_field, field_to_bn},
};

impl<'a, W: BaseExt, N: FieldExt> IntegerContext<'a, W, N> {
    fn info(&self) -> &RangeInfo<W, N> {
        &self.info
    }

    fn get_w_bn<'b>(&self, x: &'b AssignedInteger<W, N>) -> Option<&'b BigUint> {
        x.value.as_ref()
    }

    fn assign_w_ceil_leading_limb(
        &mut self,
        w: Option<BigUint>,
    ) -> Result<AssignedValue<N>, Error> {
        todo!()
    }

    fn assign_d_leading_limb(&mut self, w: Option<BigUint>) -> Result<AssignedValue<N>, Error> {
        todo!()
    }

    fn assign_w(&mut self, w: Option<BigUint>) -> Result<AssignedInteger<W, N>, Error> {
        assert!(self.info().limb_bits == COMPACT_BITS as u64);

        let mut limbs = [None as Option<AssignedValue<_>>; MAX_LIMBS];
        for i in 0..self.info().limbs as u64 {
            let v =
                (|| Some((w.as_ref()? >> (i * self.info().limb_bits)) & &self.info().limb_mask))();

            limbs[i as usize] = if i < self.info().limbs as u64 - 1 {
                Some(
                    self.range_region_context
                        .assign_compact_cell(v.as_ref().map(|x| bn_to_field(x)))?,
                )
            } else {
                Some(self.assign_w_ceil_leading_limb(v)?)
            };
        }

        let native = self.plonk_region_context.sum_with_constant_in_one_line(
            limbs
                .iter()
                .take(self.info().limbs as usize)
                .map(|x| x.as_ref().unwrap() as _)
                .zip(self.info.clone().limb_coeffs.iter().cloned()),
            None,
        )?;

        Ok(AssignedInteger::new(limbs.try_into().unwrap(), native, w))
    }

    fn assign_d(
        &mut self,
        d: Option<BigUint>,
    ) -> Result<([Option<AssignedValue<N>>; MAX_LIMBS], AssignedValue<N>), Error> {
        let mut limbs = [None as Option<AssignedValue<_>>; MAX_LIMBS];
        for i in 0..self.info().limbs as u64 {
            let v =
                (|| Some((d.as_ref()? >> (i * self.info().limb_bits)) & &self.info().limb_mask))();

            limbs[i as usize] = if i < self.info().limbs as u64 - 1 {
                Some(
                    self.range_region_context
                        .assign_compact_cell(v.as_ref().map(|x| bn_to_field(x)))?,
                )
            } else {
                Some(self.assign_d_leading_limb(v)?)
            };
        }

        let native = self.plonk_region_context.sum_with_constant_in_one_line(
            limbs
                .iter()
                .take(self.info().limbs as usize)
                .map(|x| x.as_ref().unwrap() as _)
                .zip(self.info.clone().limb_coeffs.iter().cloned()),
            None,
        )?;

        Ok((limbs, native))
    }

    fn add_constraints_for_mul_equation_on_native(
        &mut self,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
        d_native: &AssignedValue<N>,
        rem: &AssignedInteger<W, N>,
    ) -> Result<(), Error> {
        let info = self.info();
        let zero = N::zero();
        let one = N::one();
        self.plonk_region_context.one_line(
            [
                pair!(&a.native, zero),
                pair!(&b.native, zero),
                pair!(d_native, info.w_native),
                pair!(&rem.native, one),
            ]
            .into_iter(),
            None,
            ([-one], None),
        )?;
        Ok(())
    }

    fn add_constraints_for_mul_equation_on_limbs(
        &mut self,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
        d: [Option<AssignedValue<N>>; MAX_LIMBS],
        rem: &AssignedInteger<W, N>,
    ) {
        self.int_mul_queue
            .push((a.clone(), b.clone(), d, rem.clone()))
    }

    fn int_mul(
        &mut self,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let info = self.info();
        let a_bn = self.get_w_bn(&a);
        let b_bn = self.get_w_bn(&b);
        let (d, rem) = (|| Some((a_bn? * b_bn?).div_rem(&info.w_modulus)))().unzip();

        let rem = self.assign_w(rem)?;
        let d = self.assign_d(d)?;

        self.add_constraints_for_mul_equation_on_limbs(a, b, d.0, &rem);
        self.add_constraints_for_mul_equation_on_native(a, b, &d.1, &rem)?;

        Ok(rem)
    }

    fn assign_int_constant(&mut self, w: W) -> Result<AssignedInteger<W, N>, Error> {
        let w = field_to_bn(&w);
        let limbs_value = self.info().bn_to_limb_le_n(&w);

        let mut limbs = [None; MAX_LIMBS];
        for (i, limb) in limbs_value.into_iter().enumerate() {
            let cell = self.plonk_region_context.assign_constant(limb)?;
            limbs[i] = Some(cell);
        }

        let native = self
            .plonk_region_context
            .assign_constant(bn_to_field(&(&w % &self.info().n_modulus)))?;

        Ok(AssignedInteger::new(limbs, native, Some(w)))
    }
}
