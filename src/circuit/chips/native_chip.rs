use halo2_proofs::{arithmetic::FieldExt, plonk::Error};

use crate::{
    assign::{AssignedCondition, AssignedValue, MayAssignedValue},
    context::PlonkRegionContext,
    pair,
    plonk_gate::{MUL_COLUMNS, VAR_COLUMNS},
};

impl<'a, N: FieldExt> NativeChipOps<N> for PlonkRegionContext<'a, N> {
    fn var_columns(&mut self) -> usize {
        VAR_COLUMNS
    }

    fn mul_columns(&mut self) -> usize {
        MUL_COLUMNS
    }

    fn one_line<'b, const L: usize>(
        &mut self,
        native_coeff_pairs: impl Iterator<Item = (&'b dyn MayAssignedValue<N>, N)>,
        constant: Option<N>,
        mul_next_coeffs: ([N; L], Option<N>),
    ) -> Result<[Option<AssignedValue<N>>; VAR_COLUMNS], Error> {
        self.assign_one_line(
            native_coeff_pairs,
            None,
            constant,
            mul_next_coeffs.0,
            mul_next_coeffs.1,
        )
    }

    fn one_line_with_last<'b, const L: usize>(
        &mut self,
        native_coeff_pairs: impl Iterator<Item = (&'b dyn MayAssignedValue<N>, N)>,
        last: (&'b dyn MayAssignedValue<N>, N),
        constant: Option<N>,
        mul_next_coeffs: ([N; L], Option<N>),
    ) -> Result<([Option<AssignedValue<N>>; VAR_COLUMNS], AssignedValue<N>), Error> {
        let res = self.assign_one_line(
            native_coeff_pairs,
            Some(last),
            constant,
            mul_next_coeffs.0,
            mul_next_coeffs.1,
        )?;
        Ok((res, res[VAR_COLUMNS - 1].clone().unwrap()))
    }
}

pub trait NativeChipOps<N: FieldExt> {
    fn var_columns(&mut self) -> usize;
    fn mul_columns(&mut self) -> usize;

    fn one_line<'a, const L: usize>(
        &mut self,
        native_coeff_pairs: impl Iterator<Item = (&'a dyn MayAssignedValue<N>, N)>,
        constant: Option<N>,
        mul_next_coeffs: ([N; L], Option<N>),
    ) -> Result<[Option<AssignedValue<N>>; VAR_COLUMNS], Error>;

    fn one_line_add<'a>(
        &mut self,
        native_coeff_pairs: impl Iterator<Item = (&'a dyn MayAssignedValue<N>, N)>,
        constant: Option<N>,
    ) -> Result<[Option<AssignedValue<N>>; VAR_COLUMNS], Error> {
        self.one_line(native_coeff_pairs, constant, ([], None))
    }

    fn one_line_with_last<'a, const L: usize>(
        &mut self,
        native_coeff_pairs: impl Iterator<Item = (&'a dyn MayAssignedValue<N>, N)>,
        last: (&'a dyn MayAssignedValue<N>, N),
        constant: Option<N>,
        mul_next_coeffs: ([N; L], Option<N>),
    ) -> Result<([Option<AssignedValue<N>>; VAR_COLUMNS], AssignedValue<N>), Error>;

    fn assign_constant(&mut self, v: N) -> Result<AssignedValue<N>, Error> {
        let one = N::one();
        let cells = self.one_line_add([pair!(&v, -one)].into_iter(), Some(v))?;

        Ok(cells[0].unwrap())
    }

    fn assign(&mut self, v: N) -> Result<AssignedValue<N>, Error> {
        self.assign_opt(Some(v))
    }

    // Witness is None in vkey setup stage.
    fn assign_opt(&mut self, v: Option<N>) -> Result<AssignedValue<N>, Error> {
        let zero = N::zero();
        let cells = self.one_line_add([pair!(&v, zero)].into_iter(), None)?;
        Ok(cells[0].unwrap())
    }

    fn assert_equal(&mut self, a: &AssignedValue<N>, b: &AssignedValue<N>) -> Result<(), Error> {
        let one = N::one();

        self.one_line_add([pair!(a, -one), pair!(b, one)].into_iter(), None)?;
        Ok(())
    }

    fn assert_equal_constant(&mut self, a: &AssignedValue<N>, b: N) -> Result<(), Error> {
        let one = N::one();
        self.one_line_add([pair!(a, -one)].into_iter(), Some(b))?;
        Ok(())
    }

    fn sum_with_constant_in_one_line<'a>(
        &mut self,
        elems: impl Iterator<Item = (&'a AssignedValue<N>, N)> + Clone,
        constant: Option<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let sum = elems
            .clone()
            .map(|(x, y)| Some(x.value()? * y))
            .reduce(|acc, x| Some(acc? + x?))
            .unwrap();
        let sum = constant.map_or_else(|| sum, |x| Some(sum? + x));

        let cells = self.one_line_with_last(
            elems.map(|(a, b)| (a as _, b)),
            (&sum, -N::one()),
            constant,
            ([], None),
        )?;

        Ok(cells.1)
    }

    fn sum_with_constant(
        &mut self,
        elems: &[(&AssignedValue<N>, N)],
        constant: Option<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let columns = self.var_columns();

        if elems.len() < columns {
            self.sum_with_constant_in_one_line(elems.into_iter().map(|x| (*x) as _), constant)
        } else {
            let (curr, tail) = elems.split_at(columns - 1);
            let mut acc = self.sum_with_constant_in_one_line(curr.iter().cloned(), constant)?;

            for chunk in tail.chunks(columns - 2) {
                let elems = chunk.into_iter().cloned().chain([(&acc, N::one())]);
                acc = self.sum_with_constant_in_one_line(elems, None)?;
            }
            Ok(acc)
        }
    }

    fn add(
        &mut self,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(self.var_columns() >= 3);

        let one = N::one();
        self.sum_with_constant(&[(a, one), (b, one)], None)
    }

    fn add_constant(&mut self, a: &AssignedValue<N>, c: N) -> Result<AssignedValue<N>, Error> {
        assert!(self.var_columns() >= 2);

        let one = N::one();
        self.sum_with_constant(&[(a, one)], Some(c))
    }

    fn sub(
        &mut self,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(self.var_columns() >= 3);

        let one = N::one();
        self.sum_with_constant(&[(a, one), (b, -one)], None)
    }

    fn mul(
        &mut self,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        self.mul_add_constant(a, b, None)
    }

    fn mul_add_constant(
        &mut self,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
        c: Option<N>,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(self.var_columns() >= 3);
        assert!(self.mul_columns() >= 1);

        let one = N::one();
        let zero = N::zero();

        let d = || -> Option<N> { Some(a.value()? * b.value()?) }();
        let d = c.map_or_else(|| d, |c| Some(d? + c));

        let cells = self.one_line_with_last(
            [pair!(a, zero), pair!(b, zero)].into_iter(),
            pair!(&d, -one),
            c,
            ([one], None),
        )?;

        Ok(cells.1)
    }

    fn mul_add(
        &mut self,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
        ab_coeff: N,
        c: &AssignedValue<N>,
        c_coeff: N,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(self.var_columns() >= 4);
        assert!(self.mul_columns() >= 1);

        let one = N::one();
        let zero = N::zero();

        let d =
            || -> Option<N> { Some(a.value()? * b.value()? * ab_coeff + c.value()? * c_coeff) }();

        let cells = self.one_line_with_last(
            [pair!(a, zero), pair!(b, zero), pair!(c, c_coeff)].into_iter(),
            pair!(&d, -one),
            None,
            ([ab_coeff], None),
        )?;

        Ok(cells.1)
    }

    fn invert_unsafe(&mut self, a: &AssignedValue<N>) -> Result<AssignedValue<N>, Error> {
        let b = a.value().map(|a| a.invert().unwrap());

        let one = N::one();
        let zero = N::zero();

        let cells = self.one_line(
            [pair!(a, zero), pair!(&b, zero)].into_iter(),
            Some(-one),
            ([one], None),
        )?;

        Ok(cells[1].unwrap())
    }

    fn invert(
        &mut self,
        a: &AssignedValue<N>,
    ) -> Result<(AssignedCondition<N>, AssignedValue<N>), Error> {
        let zero = N::zero();
        let one = N::one();
        let b = a.value().map(|a| a.invert().unwrap_or(zero));
        let c = (|| Some(one - a.value()? * b?))();

        // a * c = 0, one of them must be zero
        let cells = self.one_line(
            [pair!(a, zero), pair!(&c, zero)].into_iter(),
            None,
            ([one], None),
        )?;
        let c = cells[1].unwrap();

        // a * b + c = 1
        let cells = self.one_line(
            [pair!(a, zero), pair!(&b, zero), pair!(&c, one)].into_iter(),
            Some(-one),
            ([one], None),
        )?;

        Ok((cells[2].unwrap().into(), cells[1].unwrap()))
    }

    fn is_zero(&mut self, a: &AssignedValue<N>) -> Result<AssignedCondition<N>, Error> {
        Ok(self.invert(a)?.0)
    }

    fn div_unsafe(
        &mut self,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let c = (|| Some(b.value()?.invert().unwrap() * a.value()?))();

        let one = N::one();
        let zero = N::zero();

        // b * c = a
        let cells = self.one_line(
            [pair!(b, zero), pair!(&c, zero), pair!(a, -one)].into_iter(),
            None,
            ([one], None),
        )?;

        Ok(cells[1].unwrap())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::plonk_gate::*;
    use crate::util::test::*;
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
                || "native_chip",
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

    fn random_and_assign_non_zero(
        context: &mut PlonkRegionContext<'_, Fr>,
    ) -> Result<(Fr, AssignedValue<Fr>), Error> {
        let mut a = Fr::rand();
        while a.is_zero_vartime() {
            a = Fr::rand();
        }
        Ok((a, context.assign(a)?))
    }

    fn fill_add_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        let (a, assigned_a) = random_and_assign(context)?;
        let (b, assigned_b) = random_and_assign(context)?;

        let c = a + b + if is_success { Fr::zero() } else { Fr::one() };
        let assigned_c = context.assign(c)?;

        let sum = context.add(&assigned_a, &assigned_b)?;
        context.assert_equal(&assigned_c, &sum)?;
        Ok(())
    }

    fn fill_sub_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        let (a, assigned_a) = random_and_assign(context)?;
        let (b, assigned_b) = random_and_assign(context)?;

        let c = a - b + if is_success { Fr::zero() } else { Fr::one() };
        let assigned_c = context.assign(c)?;

        let res = context.sub(&assigned_a, &assigned_b)?;
        context.assert_equal(&assigned_c, &res)?;
        Ok(())
    }

    fn fill_mul_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        let (a, assigned_a) = random_and_assign(context)?;
        let (b, assigned_b) = random_and_assign(context)?;

        let c = a * b + if is_success { Fr::zero() } else { Fr::one() };
        let assigned_c = context.assign(c)?;

        let res = context.mul(&assigned_a, &assigned_b)?;
        context.assert_equal(&assigned_c, &res)?;
        Ok(())
    }

    fn fill_add_constant_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        let (a, assigned_a) = random_and_assign(context)?;
        let b = Fr::rand();

        let c = a + b + if is_success { Fr::zero() } else { Fr::one() };
        let assigned_c = context.assign(c)?;

        let sum = context.add_constant(&assigned_a, b)?;
        context.assert_equal(&assigned_c, &sum)?;
        Ok(())
    }

    fn fill_mul_add_constant_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        let (a, assigned_a) = random_and_assign(context)?;
        let (b, assigned_b) = random_and_assign(context)?;
        let c = Fr::rand();

        let acc = a * b + c + if is_success { Fr::zero() } else { Fr::one() };
        let assigned_acc = context.assign(acc)?;

        let res = context.mul_add_constant(&assigned_a, &assigned_b, Some(c))?;
        context.assert_equal(&assigned_acc, &res)?;
        Ok(())
    }

    fn fill_mul_add_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        let (a, assigned_a) = random_and_assign(context)?;
        let (b, assigned_b) = random_and_assign(context)?;
        let ab_coeff = Fr::rand();
        let (c, assigned_c) = random_and_assign(context)?;
        let c_coeff = Fr::rand();

        let acc = a * b * ab_coeff + c * c_coeff + if is_success { Fr::zero() } else { Fr::one() };
        let assigned_acc = context.assign(acc)?;

        let res = context.mul_add(&assigned_a, &assigned_b, ab_coeff, &assigned_c, c_coeff)?;
        context.assert_equal(&assigned_acc, &res)?;
        Ok(())
    }

    fn fill_sum_with_constant_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        for i in 1..10 {
            let mut elems = vec![];
            let mut assigned = vec![];
            let mut sum = Fr::zero();
            for _ in 0..=i {
                assigned.push(context.assign(Fr::rand())?);
            }

            for _ in 0..i {
                let c = Fr::rand();
                elems.push((&assigned[i], c));
                sum += assigned[i].value().unwrap() * c;
            }

            // gen constant
            let c = Fr::rand();
            sum += c;

            // failure test
            if !is_success {
                sum += Fr::one();
            }

            let expect = context.assign(sum)?;
            let res = context.sum_with_constant(&elems[..], Some(c))?;

            context.assert_equal(&res, &expect)?;
        }
        Ok(())
    }

    fn fill_invert_unsafe_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        let (a, assigned_a) = random_and_assign_non_zero(context)?;

        let c = a.invert().unwrap() + if is_success { Fr::zero() } else { Fr::one() };
        let assigned_c = context.assign(c)?;

        let res = context.invert_unsafe(&assigned_a)?;
        context.assert_equal(&assigned_c, &res)?;
        Ok(())
    }

    fn fill_invert_non_zero_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        let (a, assigned_a) = random_and_assign_non_zero(context)?;

        let c = a.invert().unwrap() + if is_success { Fr::zero() } else { Fr::one() };
        let assigned_c = context.assign(c)?;

        let (o, res) = context.invert(&assigned_a)?;
        context.assert_equal(&assigned_c, &res)?;
        context.assert_equal_constant(o.as_ref(), Fr::zero())?;
        Ok(())
    }

    fn fill_invert_zero_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        let assigned_zero = context.assign_constant(Fr::zero())?;
        let (o, _) = context.invert(&assigned_zero)?;
        context.assert_equal_constant(
            o.as_ref(),
            Fr::one() + if is_success { Fr::zero() } else { Fr::one() },
        )?;
        Ok(())
    }

    fn fill_is_zero_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        if is_success {
            let assigned_zero = context.assign_constant(Fr::zero())?;
            let o = context.is_zero(&assigned_zero)?;
            context.assert_equal_constant(o.as_ref(), Fr::one())?;
            let (_, assigned_non_zero) = random_and_assign_non_zero(context)?;
            let o = context.is_zero(&assigned_non_zero)?;
            context.assert_equal_constant(o.as_ref(), Fr::zero())?;
        } else {
            let case = OsRng.gen_range(0..2);
            match case {
                0 => {
                    let assigned_zero = context.assign_constant(Fr::zero())?;
                    let o = context.is_zero(&assigned_zero)?;
                    context.assert_equal_constant(o.as_ref(), Fr::zero())?;
                }
                1 => {
                    let (_, assigned_non_zero) = random_and_assign_non_zero(context)?;
                    let o = context.is_zero(&assigned_non_zero)?;
                    context.assert_equal_constant(o.as_ref(), Fr::one())?;
                }
                _ => unreachable!(),
            }
        }
        Ok(())
    }

    fn fill_div_unsafe_test(
        context: &mut PlonkRegionContext<'_, Fr>,
        is_success: bool,
    ) -> Result<(), Error> {
        if is_success {
            let assigned_zero = context.assign_constant(Fr::zero())?;
            let (a, assigned_non_zero_a) = random_and_assign_non_zero(context)?;
            let (b, assigned_non_zero_b) = random_and_assign_non_zero(context)?;
            let res = context.div_unsafe(&assigned_zero, &assigned_non_zero_a)?;
            context.assert_equal_constant(&res, Fr::zero())?;

            let res = context.div_unsafe(&assigned_non_zero_b, &assigned_non_zero_a)?;
            context.assert_equal_constant(&res, a.invert().unwrap() * b)?;
        } else {
            let assigned_zero = context.assign_constant(Fr::zero())?;
            let (a, assigned_non_zero_a) = random_and_assign_non_zero(context)?;
            let (b, assigned_non_zero_b) = random_and_assign_non_zero(context)?;
            let res = context.div_unsafe(&assigned_zero, &assigned_non_zero_a)?;
            context.assert_equal_constant(&res, Fr::one())?;

            let res = context.div_unsafe(&assigned_non_zero_b, &assigned_non_zero_a)?;
            context.assert_equal_constant(&res, a.invert().unwrap() * b + Fr::one())?;
        }
        Ok(())
    }

    #[test]
    fn test_native_chip_success() {
        run_circuit_on_bn256(
            TestCircuit {
                fill: |context| {
                    for v in [
                        fill_sum_with_constant_test,
                        fill_add_constant_test,
                        fill_add_test,
                        fill_sub_test,
                        fill_mul_add_constant_test,
                        fill_mul_add_test,
                        fill_mul_test,
                        fill_invert_unsafe_test,
                        fill_invert_non_zero_test,
                        fill_invert_zero_test,
                        fill_is_zero_test,
                        fill_div_unsafe_test,
                    ] {
                        v(context, true)?;
                    }
                    Ok(())
                },
            },
            19,
        );
    }

    #[test]
    fn test_native_chip_fail1() {
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
                fill_sum_with_constant_test,
                fill_add_constant_test,
                fill_add_test,
                fill_sub_test,
                fill_mul_add_constant_test,
                fill_mul_add_test,
                fill_mul_test,
            ] {
                test_fail!(v);
            }
        }
    }

    #[test]
    fn test_native_chip_fail2() {
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
                fill_invert_unsafe_test,
                fill_invert_non_zero_test,
                fill_invert_zero_test,
                fill_is_zero_test,
                fill_div_unsafe_test,
            ] {
                test_fail!(v);
            }
        }
    }
}
