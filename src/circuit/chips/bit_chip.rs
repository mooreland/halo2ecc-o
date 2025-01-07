use halo2_proofs::{arithmetic::FieldExt, plonk::Error};

use crate::{
    assign::{AssignedCondition, AssignedValue},
    context::PlonkRegionContext,
    pair,
};

use super::native_chip::NativeChipOps;

impl<'a, N: FieldExt> BitChipOps<N> for PlonkRegionContext<'a, N> {}

pub trait BitChipOps<N: FieldExt>: NativeChipOps<N> {
    fn assign_bit(&mut self, a: N) -> Result<AssignedCondition<N>, Error> {
        self.assign_bit_opt(Some(a))
    }

    fn assign_bit_opt(&mut self, a: Option<N>) -> Result<AssignedCondition<N>, Error> {
        let zero = N::zero();
        let one = N::one();

        let cells = self.one_line(
            [pair!(&a, one), pair!(&a, zero)].into_iter(),
            None,
            ([-one], None),
        )?;
        Ok(cells[0].unwrap().into())
    }

    fn assert_bit(&mut self, a: &AssignedValue<N>) -> Result<(), Error> {
        let zero = N::zero();
        let one = N::one();

        self.one_line(
            [pair!(a, one), pair!(a, zero)].into_iter(),
            None,
            ([-one], None),
        )?;
        Ok(())
    }

    fn and(
        &mut self,
        a: &AssignedCondition<N>,
        b: &AssignedCondition<N>,
    ) -> Result<AssignedCondition<N>, Error> {
        let res = self.mul(a.as_ref(), b.as_ref())?;

        Ok(res.into())
    }

    fn not(&mut self, a: &AssignedCondition<N>) -> Result<AssignedCondition<N>, Error> {
        let one = N::one();
        let res = self.sum_with_constant(&[(a.as_ref(), -one)], Some(one))?;

        Ok(res.into())
    }

    fn not_and(
        &mut self,
        a: &AssignedCondition<N>,
        b: &AssignedCondition<N>,
    ) -> Result<AssignedCondition<N>, Error> {
        assert!(self.var_columns() >= 3);
        assert!(self.mul_columns() >= 1);

        let one = N::one();
        let zero = N::zero();

        //let c = b - a * b;
        let c = (|| {
            Some(
                if !!a.value()?.is_zero_vartime() && !b.value()?.is_zero_vartime() {
                    one
                } else {
                    zero
                },
            )
        })();

        let cells = self.one_line(
            [
                pair!(a.as_ref(), zero),
                pair!(b.as_ref(), one),
                pair!(&c, -one),
            ]
            .into_iter(),
            None,
            ([-one], None),
        )?;

        Ok(cells[2].unwrap().into())
    }

    fn or(
        &mut self,
        a: &AssignedCondition<N>,
        b: &AssignedCondition<N>,
    ) -> Result<AssignedCondition<N>, Error> {
        let zero = N::zero();
        let one = N::one();

        //let c = a + b - a * b;
        let c = (|| {
            Some(
                if !a.value()?.is_zero_vartime() || !b.value()?.is_zero_vartime() {
                    one
                } else {
                    zero
                },
            )
        })();

        let cells = self.one_line(
            [
                pair!(a.as_ref(), one),
                pair!(b.as_ref(), one),
                pair!(&c, -one),
            ]
            .into_iter(),
            None,
            ([-one], None),
        )?;

        Ok(cells[2].unwrap().into())
    }

    fn xor(
        &mut self,
        a: &AssignedCondition<N>,
        b: &AssignedCondition<N>,
    ) -> Result<AssignedCondition<N>, Error> {
        let zero = N::zero();
        let one = N::one();
        let two = one + one;

        //let c = a + b - 2 * a * b;
        let c = (|| {
            Some(
                if !a.value()?.is_zero_vartime() ^ !b.value()?.is_zero_vartime() {
                    one
                } else {
                    zero
                },
            )
        })();

        let cells = self.one_line(
            [
                pair!(a.as_ref(), one),
                pair!(b.as_ref(), one),
                pair!(&c, -one),
            ]
            .into_iter(),
            None,
            ([-two], None),
        )?;

        Ok(cells[2].unwrap().into())
    }

    fn xnor(
        &mut self,
        a: &AssignedCondition<N>,
        b: &AssignedCondition<N>,
    ) -> Result<AssignedCondition<N>, Error> {
        let zero = N::zero();
        let one = N::one();
        let two = one + one;

        //let c = 1 - a - b + 2 * a * b;
        let c = (|| {
            Some(
                if !(!a.value()?.is_zero_vartime() ^ !b.value()?.is_zero_vartime()) {
                    one
                } else {
                    zero
                },
            )
        })();

        let cells = self.one_line(
            [
                pair!(a.as_ref(), -one),
                pair!(b.as_ref(), -one),
                pair!(&c, -one),
            ]
            .into_iter(),
            Some(one),
            ([two], None),
        )?;

        Ok(cells[2].unwrap().into())
    }

    // if cond then a else b
    fn bisec(
        &mut self,
        cond: &AssignedCondition<N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let zero = N::zero();
        let one = N::one();

        if self.var_columns() >= 5 {
            // c = cond * a - cond * b + b
            let c = (|| {
                Some(if cond.value()?.is_zero_vartime() {
                    b.value()?
                } else {
                    a.value()?
                })
            })();

            let cells = self.one_line(
                [
                    pair!(cond.as_ref(), zero),
                    pair!(a, zero),
                    pair!(cond.as_ref(), zero),
                    pair!(b, one),
                    pair!(&c, -one),
                ]
                .into_iter(),
                None,
                ([one, -one], None),
            )?;

            Ok(cells[4].unwrap())
        } else {
            let t = self.mul_add(cond.as_ref(), a, one, b, one)?;
            self.mul_add(cond.as_ref(), b, -one, &t, one)
        }
    }

    fn bisec_cond(
        &mut self,
        cond: &AssignedCondition<N>,
        a: &AssignedCondition<N>,
        b: &AssignedCondition<N>,
    ) -> Result<AssignedCondition<N>, Error> {
        let c = self.bisec(cond, a.as_ref(), b.as_ref())?;
        Ok(c.into())
    }

    fn assert_true(&mut self, a: &AssignedCondition<N>) -> Result<(), Error> {
        #[cfg(not(test))]
        assert!(a.value.map(|a| a == N::one()).unwrap_or(true));

        self.assert_equal_constant(a.as_ref(), N::one())
    }

    fn assert_false(&mut self, a: &AssignedCondition<N>) -> Result<(), Error> {
        #[cfg(not(test))]
        assert!(a.value.map(|a| a == N::zero()).unwrap_or(true));

        self.assert_equal_constant(a.as_ref(), N::zero())
    }

    fn try_assert_false(&mut self, a: &AssignedCondition<N>) -> Result<bool, Error> {
        self.assert_equal_constant(a.as_ref(), N::zero())?;
        Ok(a.value.map(|a| a == N::zero()).unwrap_or(true))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::plonk_gate::*;
    use crate::utils::test::*;
    use ark_std::{end_timer, start_timer};
    use floor_planner::V1;
    use halo2_proofs::arithmetic::BaseExt;
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::circuit::*;
    use halo2_proofs::pairing::bn256::Fr;
    use halo2_proofs::plonk::*;
    use rand::Rng;
    use rand_core::OsRng;

    #[derive(Clone, Debug)]
    struct TestCircuit<F: Clone + Fn(&mut PlonkRegionContext<'_, Fr>) -> Result<(), Error>> {
        fill: F,
    }

    impl<F: Clone + Fn(&mut PlonkRegionContext<'_, Fr>) -> Result<(), Error>> Circuit<Fr>
        for TestCircuit<F>
    {
        type Config = PlonkGateConfig;
        type FloorPlanner = V1;

        fn configure(meta: &mut ConstraintSystem<Fr>) -> PlonkGateConfig {
            PlonkGate::<Fr>::configure(meta)
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
                    let mut context = PlonkRegionContext::new(&region, &config);

                    (self.fill)(&mut context)?;

                    Ok(())
                },
            )?;
            end_timer!(timer);
            Ok(())
        }
    }

    fn random_and_assign(
        context: &mut PlonkRegionContext<'_, Fr>,
    ) -> Result<(Fr, AssignedValue<Fr>), Error> {
        let a = Fr::rand();
        Ok((a, context.assign(a)?))
    }

    fn random_and_assign_non_bit(
        context: &mut PlonkRegionContext<'_, Fr>,
    ) -> Result<(Fr, AssignedValue<Fr>), Error> {
        let mut a = Fr::rand();
        while a.is_zero_vartime() || a == Fr::one() {
            a = Fr::rand();
        }
        Ok((a, context.assign(a)?))
    }

    fn fill_assert_bit_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        if is_success {
            let assigned_zero = context.assign_constant(Fr::zero())?;
            let assigned_one = context.assign_constant(Fr::one())?;

            context.assert_bit(&assigned_zero)?;
            context.assert_bit(&assigned_one)?;
        } else {
            let (_, assigned_v) = random_and_assign_non_bit(context)?;
            context.assert_bit(&assigned_v)?;
        }
        Ok(())
    }

    fn fill_bit_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
        bit_op: impl Fn(bool, bool) -> bool,
        bit_op_circuit: impl Fn(
            &mut PlonkRegionContext<'_, Fr>,
            &AssignedCondition<Fr>,
            &AssignedCondition<Fr>,
        ) -> Result<AssignedCondition<Fr>, Error>,
    ) -> Result<(), Error> {
        if is_success {
            for a in [false, true] {
                for b in [false, true] {
                    let assigned_a = context.assign_bit(Fr::from(a as u64))?;
                    let assigned_b = context.assign_bit(Fr::from(b as u64))?;
                    let res = bit_op_circuit(context, &assigned_a, &assigned_b)?;

                    let expect = context.assign_bit(Fr::from((bit_op(a, b)) as u64))?;
                    context.assert_equal(res.as_ref(), expect.as_ref())?;
                }
            }
        } else {
            let a = OsRng.gen_bool(0.5);
            let b = OsRng.gen_bool(0.5);

            let assigned_a = context.assign_bit(Fr::from(a as u64))?;
            let assigned_b = context.assign_bit(Fr::from(b as u64))?;
            let res = bit_op_circuit(context, &assigned_a, &assigned_b)?;

            let expect = context.assign_bit(Fr::from(1 - bit_op(a, b) as u64))?;
            context.assert_equal(res.as_ref(), expect.as_ref())?;
        }
        Ok(())
    }

    fn fill_and_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        fill_bit_test(
            context,
            is_success,
            |a, b| a && b,
            |context, a, b| context.and(a, b),
        )?;
        Ok(())
    }

    fn fill_not_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        fill_bit_test(
            context,
            is_success,
            |a, _| !a,
            |context, a, _| context.not(a),
        )?;
        Ok(())
    }
    fn fill_not_and_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        fill_bit_test(
            context,
            is_success,
            |a, b| !a && b,
            |context, a, b| context.not_and(a, b),
        )?;
        Ok(())
    }

    fn fill_or_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        fill_bit_test(
            context,
            is_success,
            |a, b| a || b,
            |context, a, b| context.or(a, b),
        )?;
        Ok(())
    }

    fn fill_xor_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        fill_bit_test(
            context,
            is_success,
            |a, b| a ^ b,
            |context, a, b| context.xor(a, b),
        )?;
        Ok(())
    }

    fn fill_xnor_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        fill_bit_test(
            context,
            is_success,
            |a, b| !(a ^ b),
            |context, a, b| context.xnor(a, b),
        )?;
        Ok(())
    }

    fn fill_bisec_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        if is_success {
            for cond in [false, true] {
                let assigned_cond = context.assign_bit(Fr::from(cond as u64))?;
                let (_, assigned_a) = random_and_assign(context)?;
                let (_, assigned_b) = random_and_assign(context)?;

                let res = context.bisec(&assigned_cond, &assigned_a, &assigned_b)?;
                context.assert_equal(&res, if cond { &assigned_a } else { &assigned_b })?;
            }
        } else {
            let cond = OsRng.gen_bool(0.5);
            let assigned_cond = context.assign_bit(Fr::from(cond as u64))?;
            let (a, assigned_a) = random_and_assign(context)?;
            let (b, assigned_b) = random_and_assign(context)?;

            let res = context.bisec(&assigned_cond, &assigned_a, &assigned_b)?;

            let bad = if cond { a + Fr::one() } else { b + Fr::one() };
            let assigned_bad = context.assign(bad)?;
            context.assert_equal(&res, &assigned_bad)?;
        }
        Ok(())
    }

    fn fill_assert_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        if is_success {
            let assigned_cond = context.assign_bit(Fr::one())?;
            context.assert_true(&assigned_cond)?;
            let assigned_cond = context.assign_bit(Fr::zero())?;
            context.assert_false(&assigned_cond)?;
            assert!(context.try_assert_false(&assigned_cond)?);
        } else {
            let cond = OsRng.gen_range(0..2);
            match cond {
                0 => {
                    let assigned_cond = context.assign_bit(Fr::one())?;
                    context.assert_false(&assigned_cond)?;
                }
                1 => {
                    let assigned_cond = context.assign_bit(Fr::zero())?;
                    context.assert_true(&assigned_cond)?;
                }
                _ => unreachable!(),
            }
        }
        Ok(())
    }

    #[test]
    fn test_native_chip_success() {
        run_circuit_on_bn256(
            TestCircuit {
                fill: |context| {
                    let is_success = true;

                    for v in [
                        fill_assert_bit_test,
                        fill_and_test,
                        fill_not_test,
                        fill_not_and_test,
                        fill_or_test,
                        fill_xor_test,
                        fill_xnor_test,
                        fill_bisec_test,
                        fill_assert_test,
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
    fn test_native_chip_fail() {
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
                fill_assert_bit_test,
                fill_and_test,
                fill_not_test,
                fill_not_and_test,
                fill_or_test,
                fill_xor_test,
                fill_xnor_test,
                fill_bisec_test,
                fill_assert_test,
            ] {
                test_fail!(v);
            }
        }
    }
}
