use ark_std::One;
use halo2_proofs::{
    arithmetic::{BaseExt, FieldExt},
    plonk::Error,
};
use num_bigint::BigUint;
use num_integer::Integer;

use crate::{
    assign::{AssignedCondition, AssignedInteger, AssignedValue, MAX_LIMBS},
    chips::native_chip::NativeChipOps,
    context::IntegerContext,
    pair,
    range_gate::{COMPACT_BITS, COMPACT_CELLS},
    range_info::{
        get_bn_common_range_to_field, get_bn_compact_range, RangeInfo, COMMON_RANGE_BITS,
    },
    util::{bn_to_field, field_to_bn, get_n_from_i32, ToField},
};

use super::bit_chip::BitChipOps;

impl<'a, W: BaseExt, N: FieldExt> IntegerContext<'a, W, N> {
    pub fn info(&self) -> &RangeInfo<W, N> {
        &self.info
    }

    pub fn get_w_bn<'b>(&self, x: &'b AssignedInteger<W, N>) -> Option<&'b BigUint> {
        x.value.as_ref()
    }

    //TODO: review again
    fn assign_leading_limb(
        &mut self,
        v: Option<BigUint>,
        leading_bits: u64,
        decompose: usize,
    ) -> Result<AssignedValue<N>, Error> {
        let mut parts = [None; COMPACT_CELLS];

        for i in 0..decompose {
            let curr_value = (|| Some(get_bn_common_range_to_field(v.as_ref()?, i as u64)))();

            parts[i as usize] = Some(if i < decompose - 1 {
                self.range_region_context
                    .assign_common_range_cell(curr_value)
            } else {
                self.range_region_context
                    .assign_custom_range_cell(curr_value, get_n_from_i32((1 << leading_bits) - 1))
            }?);
        }

        let res = self.plonk_region_context.sum_with_constant_in_one_line(
            parts.iter().filter_map(|x| x.as_ref()).zip(
                (0..decompose)
                    .map(|i| (BigUint::one() << (i as u64 * COMMON_RANGE_BITS)).to_field()),
            ),
            None,
        )?;

        Ok(res)
    }

    fn assign_w_ceil_leading_limb(
        &mut self,
        w: Option<BigUint>,
    ) -> Result<AssignedValue<N>, Error> {
        self.assign_leading_limb(
            w,
            self.info().w_ceil_leading_bits,
            self.info().w_ceil_leading_decompose as usize,
        )
    }

    fn assign_d_leading_limb(&mut self, w: Option<BigUint>) -> Result<AssignedValue<N>, Error> {
        self.assign_leading_limb(
            w,
            self.info().d_leading_bits,
            self.info().d_leading_decompose as usize,
        )
    }

    pub fn assign_w(&mut self, w: Option<BigUint>) -> Result<AssignedInteger<W, N>, Error> {
        assert!(self.info().limb_bits == COMPACT_BITS as u64);
        assert!(self.info().w_ceil_bits > (self.info().limbs - 1) * self.info().limb_bits);
        assert!(self.info().w_ceil_bits <= self.info().limbs * self.info().limb_bits);

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

    fn limbs_to_native(
        &mut self,
        &limbs: &[Option<AssignedValue<N>>; MAX_LIMBS],
    ) -> Result<AssignedValue<N>, Error> {
        let native = self.plonk_region_context.sum_with_constant_in_one_line(
            limbs
                .iter()
                .take(self.info().limbs as usize)
                .map(|x| x.as_ref().unwrap() as _)
                .zip(self.info.clone().limb_coeffs.iter().cloned()),
            None,
        )?;

        Ok(native)
    }

    fn assign_d(
        &mut self,
        d: Option<BigUint>,
    ) -> Result<([Option<AssignedValue<N>>; MAX_LIMBS], AssignedValue<N>), Error> {
        assert!(self.info().d_bits > (self.info().limbs - 1) * self.info().limb_bits);
        assert!(self.info().d_bits <= self.info().limbs * self.info().limb_bits);

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

        let native = self.limbs_to_native(&limbs)?;

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

    pub fn int_mul(
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

    pub fn assign_int_constant(&mut self, w: W) -> Result<AssignedInteger<W, N>, Error> {
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

    pub fn assert_int_exact_equal(
        &mut self,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<(), Error> {
        self.plonk_region_context
            .assert_equal(&a.native, &b.native)?;
        for i in 0..self.info().reduce_check_limbs as usize {
            self.plonk_region_context
                .assert_equal(&a.limbs_le[i].unwrap(), &b.limbs_le[i].unwrap())?;
        }
        Ok(())
    }

    pub fn finalize_int_mul(&mut self) -> Result<(), Error> {
        let mut queue = vec![];
        std::mem::swap(&mut queue, &mut self.int_mul_queue);

        for (a, b, d, rem) in &queue {
            self.assign_int_mul_core(a, b, d, rem)?;
        }

        Ok(())
    }

    pub fn reduce(&mut self, a: &AssignedInteger<W, N>) -> Result<AssignedInteger<W, N>, Error> {
        if a.times == 1 {
            return Ok(a.clone());
        }

        let overflow_limit = self.info().overflow_limit;
        assert!(a.times < overflow_limit as usize);

        // Check a = d * w + rem
        let a_bn = self.get_w_bn(&a);
        let (d, rem) = (|| Some(a_bn?.div_rem(&self.info().w_modulus)))().unzip();
        let assigned_rem = self.assign_w(rem.clone())?;

        // Witness stage, can be batch into GPU
        let zero = N::zero();
        let one = N::one();

        let d = (|| Some(bn_to_field(d.as_ref()?)))();
        let assigned_d = self.range_region_context.assign_common_range_cell(d)?;
        let d = d.map(|x| field_to_bn(&x));

        // Constrain on native.
        self.plonk_region_context.one_line(
            [
                pair!(&assigned_d, self.info().w_native),
                pair!(&assigned_rem.native, one),
                pair!(&a.native, -one),
            ]
            .into_iter(),
            None,
            ([], None),
        )?;

        // Check equation on n limbs
        // so we have
        // `a = d * w + rem (mod in 2 ^ (limb_bits) ^ n)`
        // `a = d * w + rem (mod native)`
        // ->
        // `a = d * w + rem (mod in lcm(native, 2 ^ (limb_bits) ^ n))`

        // To ensure completeness
        // `max_a = w_ceil * overflow_limit < lcm(native, 2 ^ (limb_bits) ^ n))`

        // In each limb check, we need to find a `v`, that
        // `d *w.limb[i] + rem.limb[i] - a.limb[i] + overflow_limit * limb_modulus + carry = v * limb_modulus`
        // To ensure `v < limb_modulus`
        // `max(d * w.limb[i] + rem.limb[i] - a.limb[i] + overflow_limit * limb_modulus + carry) / limb_modulus`
        // = `(common_modulus * limb_modulus + limb_modulus + overflow_limit * limb_modulus + limb_modulus) / limb_modulus`
        // = `(common_modulus + 1 + overflow_limit + 1)`
        // = `(common_modulus + overflow_limit + 2)` <= limb_modulus

        let mut last_v: Option<AssignedValue<N>> = None;
        for i in 0..self.info().reduce_check_limbs as usize {
            // check equation on ith limbs
            let last_borrow = if i != 0 { overflow_limit } else { 0 };
            let carry = (|| Some(field_to_bn(last_v?.value().as_ref()?)))();

            let u: Option<BigUint> = (|| {
                Some(
                    d.as_ref()? * &self.info().w_modulus_limbs_le_bn[i]
                        + get_bn_compact_range(rem.as_ref()?, i as u64)
                        + &self.info().limb_modulus * overflow_limit
                        - field_to_bn(&a.limbs_le[i].unwrap().value()?)
                        + carry.unwrap_or(BigUint::from(0u64))
                        - last_borrow,
                )
            })();

            let (v, _) = (|| Some(u?.div_rem(&self.info().limb_modulus)))().unzip();

            let v = self
                .range_region_context
                .assign_common_range_cell(v.map(|v| bn_to_field(&v)))?;

            // constrains on limb_modulus
            self.plonk_region_context.one_line(
                [
                    pair!(&assigned_d, self.info().w_modulus_limbs_le[i]),
                    pair!(&assigned_rem.limbs_le[i].unwrap(), one),
                    pair!(&a.limbs_le[i].unwrap(), -one),
                    pair!(&v, -bn_to_field::<N>(&self.info().limb_modulus)),
                    match &last_v {
                        Some(last_v) => pair!(last_v, one),
                        None => pair!(&zero, zero),
                    },
                ]
                .into_iter(),
                Some(bn_to_field(
                    &(&self.info().limb_modulus * overflow_limit
                        - if i == 0 { 0u64 } else { overflow_limit }),
                )),
                ([], None),
            )?;

            last_v = Some(v);
        }

        Ok(assigned_rem)
    }

    // Same as reduce, but res is zero
    // TODO: review again
    pub fn assert_int_zero(&mut self, a: &AssignedInteger<W, N>) -> Result<(), Error> {
        let overflow_limit = self.info().overflow_limit;
        assert!(a.times < overflow_limit as usize);

        // Check a = d * w
        let a_bn = self.get_w_bn(&a);
        let (d, _) = (|| Some(a_bn?.div_rem(&self.info().w_modulus)))().unzip();

        let zero = N::zero();
        let one = N::one();

        let d = (|| Some(bn_to_field(d.as_ref()?)))();
        let assigned_d = self.range_region_context.assign_common_range_cell(d)?;
        let d = d.map(|x| field_to_bn(&x));

        // Constrain on native.
        self.plonk_region_context.one_line(
            [
                pair!(&assigned_d, self.info().w_native),
                pair!(&a.native, -one),
            ]
            .into_iter(),
            None,
            ([], None),
        )?;

        let mut last_v: Option<AssignedValue<N>> = None;
        for i in 0..self.info().reduce_check_limbs as usize {
            // check equation on ith limbs
            let last_borrow = if i != 0 { overflow_limit } else { 0 };
            let carry = (|| Some(field_to_bn(last_v?.value().as_ref()?)))();

            let u: Option<BigUint> = (|| {
                Some(
                    d.as_ref()? * &self.info().w_modulus_limbs_le_bn[i]
                        + &self.info().limb_modulus * overflow_limit
                        - field_to_bn(&a.limbs_le[i].unwrap().value()?)
                        + carry.unwrap_or(BigUint::from(0u64))
                        - last_borrow,
                )
            })();

            let (v, _) = (|| Some(u?.div_rem(&self.info().limb_modulus)))().unzip();

            let v = self
                .range_region_context
                .assign_common_range_cell(v.map(|v| bn_to_field(&v)))?;

            // constrains on limb_modulus
            self.plonk_region_context.one_line(
                [
                    pair!(&assigned_d, self.info().w_modulus_limbs_le[i]),
                    pair!(&a.limbs_le[i].unwrap(), -one),
                    pair!(&v, -bn_to_field::<N>(&self.info().limb_modulus)),
                    match &last_v {
                        Some(last_v) => pair!(last_v, one),
                        None => pair!(&zero, zero),
                    },
                ]
                .into_iter(),
                Some(bn_to_field(
                    &(&self.info().limb_modulus * overflow_limit
                        - if i == 0 { 0u64 } else { overflow_limit }),
                )),
                ([], None),
            )?;

            last_v = Some(v);
        }

        Ok(())
    }

    pub fn conditionally_reduce(
        &mut self,
        a: AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let threshold = 1 << (self.info().overflow_bits - 2);
        if a.times > threshold {
            self.reduce(&a)
        } else {
            Ok(a)
        }
    }

    pub fn int_add(
        &mut self,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let mut limbs = [None; MAX_LIMBS];

        for i in 0..self.info().limbs as usize {
            let value = self
                .plonk_region_context
                .add(&a.limbs_le[i].unwrap(), &b.limbs_le[i].unwrap())?;
            limbs[i] = Some(value)
        }

        let native = self.limbs_to_native(&limbs)?;

        let res = AssignedInteger::new_with_times(
            limbs,
            native,
            (|| Some(a.value.as_ref()? + b.value.as_ref()?))(),
            a.times + b.times,
        );

        self.conditionally_reduce(res)
    }

    pub fn int_add_constant_w(
        &mut self,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let mut limbs = [None; MAX_LIMBS];

        for i in 0..self.info().limbs as usize {
            let value = self
                .plonk_region_context
                .add_constant(&a.limbs_le[i].unwrap(), self.info().w_modulus_limbs_le[i])?;
            limbs[i] = Some(value)
        }

        let native = self.limbs_to_native(&limbs)?;

        let res = AssignedInteger::new_with_times(
            limbs,
            native,
            a.value.as_ref().map(|a| a + &self.info().w_modulus),
            a.times + 2,
        );

        self.conditionally_reduce(res)
    }

    pub fn int_sub(
        &mut self,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let mut upper_limbs = [N::zero(); MAX_LIMBS];
        upper_limbs.copy_from_slice(
            &self.info().w_modulus_of_ceil_times[b.times as usize]
                .as_ref()
                .unwrap()
                .1,
        );

        let one = N::one();

        let mut limbs = [None; MAX_LIMBS];
        for i in 0..self.info().limbs as usize {
            let cell = self.plonk_region_context.sum_with_constant(
                &[
                    (&a.limbs_le[i].unwrap(), one),
                    (&b.limbs_le[i].unwrap(), -one),
                ],
                Some(upper_limbs[i]),
            )?;
            limbs[i] = Some(cell);
        }

        let native = self.limbs_to_native(&limbs)?;

        let upper_bn = &self.info().w_modulus_of_ceil_times[b.times as usize]
            .as_ref()
            .unwrap()
            .0;
        let res = AssignedInteger::new_with_times(
            limbs,
            native,
            a.value
                .as_ref()
                .and_then(|a| Some(a + upper_bn - b.value.as_ref()?)),
            a.times + b.times + 1,
        );
        self.conditionally_reduce(res)
    }

    pub fn int_neg(&mut self, a: &AssignedInteger<W, N>) -> Result<AssignedInteger<W, N>, Error> {
        let mut upper_limbs = [N::zero(); MAX_LIMBS];
        upper_limbs.copy_from_slice(
            &self.info().w_modulus_of_ceil_times[a.times as usize]
                .as_ref()
                .unwrap()
                .1,
        );

        let one = N::one();

        let mut limbs = [None; MAX_LIMBS];
        for i in 0..self.info().limbs as usize {
            let cell = self
                .plonk_region_context
                .sum_with_constant(&[(&a.limbs_le[i].unwrap(), -one)], Some(upper_limbs[i]))?;
            limbs[i] = Some(cell);
        }

        let native = self.limbs_to_native(&limbs)?;

        let upper_bn = &self.info().w_modulus_of_ceil_times[a.times as usize]
            .as_ref()
            .unwrap()
            .0;
        let res = AssignedInteger::new_with_times(
            limbs.try_into().unwrap(),
            native,
            a.value.as_ref().map(|a| upper_bn - a),
            a.times + 1,
        );
        self.conditionally_reduce(res)
    }

    fn assert_int_equal(
        &mut self,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<(), Error> {
        let diff = self.int_sub(a, b)?;
        self.assert_int_zero(&diff)?;
        Ok(())
    }

    fn is_pure_zero(&mut self, a: &AssignedInteger<W, N>) -> Result<AssignedCondition<N>, Error> {
        let one = N::one();

        let sum = self.plonk_region_context.sum_with_constant_in_one_line(
            a.limbs_le
                .iter()
                .filter_map(|v| v.as_ref())
                .map(|v| (v, one)),
            None,
        )?;
        self.plonk_region_context.is_zero(&sum)
    }

    fn is_pure_w_modulus(
        &mut self,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedCondition<N>, Error> {
        assert!(a.times == 1);

        let native_diff = self
            .plonk_region_context
            .add_constant(&a.native, -self.info().w_native)?;
        let mut is_eq = self.plonk_region_context.is_zero(&native_diff)?;

        for i in 0..self.info().pure_w_check_limbs as usize {
            let limb_diff = self
                .plonk_region_context
                .add_constant(&a.limbs_le[i].unwrap(), -self.info().w_modulus_limbs_le[i])?;
            let is_limb_eq = self.plonk_region_context.is_zero(&limb_diff)?;
            is_eq = self.plonk_region_context.and(&is_eq, &is_limb_eq)?;
        }

        Ok(is_eq)
    }

    fn is_int_zero(&mut self, a: &AssignedInteger<W, N>) -> Result<AssignedCondition<N>, Error> {
        let a = self.reduce(a)?;
        let is_zero = self.is_pure_zero(&a)?;
        let is_w_modulus = self.is_pure_w_modulus(&a)?;

        self.plonk_region_context.or(&is_zero, &is_w_modulus)
    }

    // TODO: review again, consider setup stage
    // Find res = a * b_inv
    // Get c = b * res.
    // Assert c - a == 0.
    // Return res.
    pub fn int_div_unsafe(
        &mut self,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<Option<AssignedInteger<W, N>>, Error> {
        let a_bn = self.get_w_bn(&a);
        let b_bn = self.get_w_bn(&b);
        let b_inv: Option<Option<W>> = b_bn.as_ref().map(|b_bn| {
            bn_to_field::<W>(&(*b_bn % &self.info().w_modulus))
                .invert()
                .into()
        });

        let res = (|| Some(bn_to_field::<W>(&(a_bn? % &self.info().w_modulus)) * b_inv??))();
        let assigned_res = self.assign_w(res.map(|res| field_to_bn(&res)))?;

        // To ensure b * res == a
        let c = self.int_mul(&b, &assigned_res)?;
        self.assert_int_equal(&c, a)?;

        // To avoid 0 / 0, we need to check b != 0
        // But to avoid reduce, we just need to check c != 0
        let is_b_zero = self.is_int_zero(&c)?;
        let is_not_zero = self.plonk_region_context.try_assert_false(&is_b_zero)?;

        if is_not_zero {
            Ok(Some(assigned_res))
        } else {
            Ok(None)
        }
    }

    pub fn int_div(
        &mut self,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<(AssignedCondition<N>, AssignedInteger<W, N>), Error> {
        // If b != 0
        // Find (c, d) that b * c = d * w + reduced_a,
        // Call reduce on `a` because if b = 1, we cannot find such (c, d), c < w_ceil and d >= 0

        // If b == 0
        // Find (c, d) that b * c = d * w + reduced_a * 0,

        let a = self.reduce(a)?;
        let b = self.reduce(b)?;
        let is_b_zero = self.is_int_zero(&b)?;
        let a_coeff = self.plonk_region_context.not(&is_b_zero)?;

        let a = {
            let mut limbs_le = [None; MAX_LIMBS];
            for i in 0..self.info().limbs as usize {
                let cell = self
                    .plonk_region_context
                    .mul(&a.limbs_le[i].unwrap(), a_coeff.as_ref())?;
                limbs_le[i] = Some(cell);
            }
            let native = self.plonk_region_context.mul(&a.native, a_coeff.as_ref())?;
            let value = (|| {
                Some(if is_b_zero.value()?.is_zero_vartime() {
                    a.value?
                } else {
                    BigUint::from(0u64)
                })
            })();
            AssignedInteger::<W, N>::new_with_times(limbs_le, native, value, a.times)
        };

        let a_bn = self.get_w_bn(&a);
        let b_bn = self.get_w_bn(&b);
        let c = (|| {
            let a_bn = a_bn?;
            Some(
                bn_to_field::<W>(b_bn.as_ref()?)
                    .invert()
                    .map(|b| bn_to_field::<W>(a_bn) * b)
                    .unwrap_or(W::zero()),
            )
        })();
        let c_bn = c.as_ref().map(|c| field_to_bn(c));
        let d_bn = (|| Some((b_bn? * c_bn.as_ref()? - a_bn?) / &self.info().w_modulus))();

        let c = self.assign_w(c_bn)?;
        let d = self.assign_d(d_bn)?;

        self.add_constraints_for_mul_equation_on_limbs(&b, &c, d.0, &a);
        self.add_constraints_for_mul_equation_on_native(&b, &c, &d.1, &a)?;

        Ok((is_b_zero, c))
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;
    use crate::context::PlonkRegionContext;
    use crate::context::RangeRegionContext;
    use crate::int_mul_gate::IntMulGate;
    use crate::int_mul_gate::IntMulGateConfig;
    use crate::plonk_gate::*;
    use crate::range_gate::RangeGate;
    use crate::range_gate::RangeGateConfig;
    use crate::util::test::*;
    use ark_std::{end_timer, start_timer};
    use floor_planner::V1;
    use halo2_proofs::arithmetic::BaseExt;
    use halo2_proofs::circuit::*;
    use halo2_proofs::pairing::bn256::{Fq, Fr};
    use halo2_proofs::plonk::*;

    #[derive(Clone, Debug)]
    struct TestCircuit<F: Clone + Fn(&mut IntegerContext<'_, Fq, Fr>) -> Result<(), Error>> {
        fill: F,
    }

    impl<F: Clone + Fn(&mut IntegerContext<'_, Fq, Fr>) -> Result<(), Error>> Circuit<Fr>
        for TestCircuit<F>
    {
        type Config = (PlonkGateConfig, RangeGateConfig, IntMulGateConfig);
        type FloorPlanner = V1;

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let plonk_gate_config = PlonkGate::<Fr>::configure(meta);
            let range_gate_config = RangeGate::configure(meta);
            let int_mul_gate_config =
                IntMulGate::configure(meta, plonk_gate_config.var, &RangeInfo::<Fq, Fr>::new());
            (plonk_gate_config, range_gate_config, int_mul_gate_config)
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
                    let plonk_region_context = PlonkRegionContext::new(&region, &config.0);
                    let range_region_context = RangeRegionContext::new(&region, &config.1);
                    let mut int_context = IntegerContext::new(
                        plonk_region_context,
                        range_region_context,
                        &config.2,
                        Arc::new(RangeInfo::new()),
                    );

                    int_context.range_region_context.init()?;
                    (self.fill)(&mut int_context)?;
                    int_context.finalize_int_mul()?;
                    int_context.range_region_context.finalize_compact_cells()?;

                    Ok(())
                },
            )?;
            end_timer!(timer);
            Ok(())
        }
    }

    fn int_random_and_assign(
        context: &mut IntegerContext<'_, Fq, Fr>,
    ) -> Result<(Fq, AssignedInteger<Fq, Fr>), Error> {
        let a = Fq::rand();
        Ok((a, context.assign_w(Some(field_to_bn(&a)))?))
    }

    fn int_random_and_assign_non_zero(
        context: &mut IntegerContext<'_, Fq, Fr>,
    ) -> Result<(Fq, AssignedInteger<Fq, Fr>), Error> {
        let mut a = Fq::rand();
        while a.ct_is_zero().into() {
            a = Fq::rand();
        }
        Ok((a, context.assign_w(Some(field_to_bn(&a)))?))
    }

    fn fill_int_mul_test(
        context: &mut IntegerContext<'_, Fq, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        if is_success {
            let (a, assigned_a) = int_random_and_assign(context)?;
            let (b, assigned_b) = int_random_and_assign(context)?;
            let c = a * b;
            let assigned_c = context.assign_w(Some(field_to_bn(&c)))?;

            let res = context.int_mul(&assigned_a, &assigned_b)?;
            context.assert_int_exact_equal(&res, &assigned_c)?;
        } else {
            let (a, assigned_a) = int_random_and_assign(context)?;
            let (b, assigned_b) = int_random_and_assign(context)?;
            let c = a * b + Fq::one();
            let assigned_c = context.assign_w(Some(field_to_bn(&c)))?;

            let res = context.int_mul(&assigned_a, &assigned_b)?;
            context.assert_int_exact_equal(&res, &assigned_c)?;
        }
        Ok(())
    }

    fn fill_int_add_test(
        context: &mut IntegerContext<'_, Fq, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        if is_success {
            let (a, assigned_a) = int_random_and_assign(context)?;
            let (b, assigned_b) = int_random_and_assign(context)?;
            let c = a + b;
            let assigned_c = context.assign_w(Some(field_to_bn(&c)))?;

            let res = context.int_add(&assigned_a, &assigned_b)?;
            let res = context.reduce(&res)?;
            context.assert_int_exact_equal(&res, &assigned_c)?;
        } else {
            let (a, assigned_a) = int_random_and_assign(context)?;
            let (b, assigned_b) = int_random_and_assign(context)?;
            let c = a * b + Fq::one();
            let assigned_c = context.assign_w(Some(field_to_bn(&c)))?;

            let res = context.int_add(&assigned_a, &assigned_b)?;
            let res = context.reduce(&res)?;
            context.assert_int_exact_equal(&res, &assigned_c)?;
        }
        Ok(())
    }

    fn fill_int_sub_test(
        context: &mut IntegerContext<'_, Fq, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        if is_success {
            let (a, assigned_a) = int_random_and_assign(context)?;
            let (b, assigned_b) = int_random_and_assign(context)?;
            let c = a - b;
            let assigned_c = context.assign_w(Some(field_to_bn(&c)))?;

            let res = context.int_sub(&assigned_a, &assigned_b)?;
            let res = context.reduce(&res)?;
            context.assert_int_exact_equal(&res, &assigned_c)?;
        } else {
            let (a, assigned_a) = int_random_and_assign(context)?;
            let (b, assigned_b) = int_random_and_assign(context)?;
            let c = a - b + Fq::one();
            let assigned_c = context.assign_w(Some(field_to_bn(&c)))?;

            let res = context.int_sub(&assigned_a, &assigned_b)?;
            let res = context.reduce(&res)?;
            context.assert_int_exact_equal(&res, &assigned_c)?;
        }
        Ok(())
    }

    fn fill_int_neg_test(
        context: &mut IntegerContext<'_, Fq, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        if is_success {
            let (a, assigned_a) = int_random_and_assign(context)?;
            let c = -a;
            let assigned_c = context.assign_w(Some(field_to_bn(&c)))?;

            let res = context.int_neg(&assigned_a)?;
            let res = context.reduce(&res)?;
            context.assert_int_exact_equal(&res, &assigned_c)?;
        } else {
            let (a, assigned_a) = int_random_and_assign(context)?;
            let c = Fq::one() - a;
            let assigned_c = context.assign_w(Some(field_to_bn(&c)))?;

            let res = context.int_neg(&assigned_a)?;
            let res = context.reduce(&res)?;
            context.assert_int_exact_equal(&res, &assigned_c)?;
        }
        Ok(())
    }

    fn fill_int_add_constant_w_test(
        context: &mut IntegerContext<'_, Fq, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        if is_success {
            let (_, assigned_a) = int_random_and_assign(context)?;

            let res = context.int_add_constant_w(&assigned_a)?;
            let res = context.reduce(&res)?;
            context.assert_int_exact_equal(&res, &assigned_a)?;
        } else {
            let (_, assigned_a) = int_random_and_assign(context)?;

            let res = context.int_add_constant_w(&assigned_a)?;
            context.assert_int_exact_equal(&res, &assigned_a)?;
        }
        Ok(())
    }

    fn fill_int_div_unsafe_test(
        context: &mut IntegerContext<'_, Fq, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        use halo2_proofs::arithmetic::Field;

        if is_success {
            let (a, assigned_a) = int_random_and_assign(context)?;
            let (b, assigned_b) = int_random_and_assign_non_zero(context)?;

            let c = a * b.invert().unwrap();
            let assigned_c = context.assign_w(Some(field_to_bn(&c)))?;

            let res = context.int_div_unsafe(&assigned_a, &assigned_b)?.unwrap();
            context.assert_int_equal(&res, &assigned_c)?;
        } else {
            let (a, assigned_a) = int_random_and_assign(context)?;
            let (b, assigned_b) = int_random_and_assign_non_zero(context)?;

            let c = a * b.invert().unwrap() + Fq::one();
            let assigned_c = context.assign_w(Some(field_to_bn(&c)))?;

            let res = context.int_div_unsafe(&assigned_a, &assigned_b)?.unwrap();
            context.assert_int_equal(&res, &assigned_c)?;
        }
        Ok(())
    }

    fn fill_int_div_test(
        context: &mut IntegerContext<'_, Fq, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        use halo2_proofs::arithmetic::Field;

        if is_success {
            let (a, assigned_a) = int_random_and_assign(context)?;
            let (b, assigned_b) = int_random_and_assign_non_zero(context)?;

            let c = a * b.invert().unwrap();
            let assigned_c = context.assign_w(Some(field_to_bn(&c)))?;

            let res = context.int_div(&assigned_a, &assigned_b)?;
            context.assert_int_equal(&res.1, &assigned_c)?;
            context.plonk_region_context.assert_false(&res.0)?;

            let assigned_zero = context.assign_w(Some(BigUint::from(0u64)))?;
            let res = context.int_div(&assigned_a, &assigned_zero)?;
            context.plonk_region_context.assert_true(&res.0)?;
        } else {
            //TESTTODO: add more case
            let (_, assigned_a) = int_random_and_assign(context)?;
            let assigned_zero = context.assign_w(Some(BigUint::from(0u64)))?;
            let res = context.int_div(&assigned_a, &assigned_zero)?;
            context.plonk_region_context.assert_false(&res.0)?;
        }
        Ok(())
    }

    #[test]
    fn test_int_chip_success() {
        run_circuit_on_bn256(
            TestCircuit {
                fill: |context| {
                    let is_success = true;

                    for v in [
                        fill_int_mul_test,
                        fill_int_add_test,
                        fill_int_add_constant_w_test,
                        fill_int_sub_test,
                        fill_int_neg_test,
                        fill_int_div_unsafe_test,
                        fill_int_div_test,
                    ] {
                        v(context, is_success)?;
                    }

                    Ok(())
                },
            },
            19,
        );
    }

    #[test]
    fn test_int_chip_fail() {
        macro_rules! test_fail {
            ($f: expr) => {
                run_circuit_on_bn256_expect_fail(
                    TestCircuit {
                        fill: |context| $f(context, false),
                    },
                    19,
                );
            };
        }
        for _ in 0..10 {
            for v in [
                fill_int_mul_test,
                fill_int_add_test,
                fill_int_add_constant_w_test,
                fill_int_sub_test,
                fill_int_neg_test,
                fill_int_div_unsafe_test,
                fill_int_div_test,
            ] {
                test_fail!(v);
            }
        }
    }
}
