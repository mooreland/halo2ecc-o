use ark_std::One;
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
    range_gate::{COMPACT_BITS, COMPACT_CELLS},
    range_info::{RangeInfo, COMMON_RANGE_BITS},
    util::{bn_to_field, field_to_bn, ToField},
};

fn get_bn_common_range_to_field<N: BaseExt>(bn: &BigUint, i: u64) -> N {
    let mask = BigUint::from((1u64 << COMMON_RANGE_BITS) - 1);
    ((bn >> (i * COMMON_RANGE_BITS)) & &mask).to_field()
}

fn get_n_from_i32<N: FieldExt>(v: i32) -> N {
    if v >= 0 {
        N::from(v as u64)
    } else {
        N::from((-v) as u64)
    }
}

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

        //println!("offset1 is {}", self.plonk_region_context.offset);
        self.add_constraints_for_mul_equation_on_limbs(a, b, d.0, &rem);
        //println!("offset2 is {}", self.plonk_region_context.offset);
        self.add_constraints_for_mul_equation_on_native(a, b, &d.1, &rem)?;
        //println!("offset3 is {}", self.plonk_region_context.offset);

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
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;
    use crate::context::PlonkRegionContext;
    use crate::context::RangeRegionContext;
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
        type Config = (PlonkGateConfig, RangeGateConfig);
        type FloorPlanner = V1;

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            (PlonkGate::<Fr>::configure(meta), RangeGate::configure(meta))
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
                        Arc::new(RangeInfo::new()),
                    );

                    int_context.range_region_context.init()?;
                    (self.fill)(&mut int_context)?;
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

    #[test]
    fn test_int_chip_success() {
        run_circuit_on_bn256(
            TestCircuit {
                fill: |context| {
                    let is_success = true;

                    for v in [fill_int_mul_test] {
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
        //for _ in 0..100 {
        {
            for v in [fill_int_mul_test] {
                test_fail!(v);
            }
        }
    }
}
