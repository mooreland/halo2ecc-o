use halo2_proofs::{arithmetic::FieldExt, plonk::Error};

use crate::{
    assign::{AssignedValue, MayAssignedValue},
    context::PlonkRegionContext,
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

macro_rules! pair {
    ($a:expr, $b:expr) => {
        ($a as _, $b)
    };
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
        let zero = N::zero();
        let cells = self.one_line_add([pair!(&v, zero)].into_iter(), None)?;
        Ok(cells[0].unwrap())
    }

    fn assert_equal(&mut self, a: &AssignedValue<N>, b: &AssignedValue<N>) -> Result<(), Error> {
        let one = N::one();

        self.one_line_add([pair!(a, -one), pair!(b, one)].into_iter(), None)?;
        Ok(())
    }

    fn sum_with_constant_in_one_line<'a>(
        &mut self,
        elems: impl Iterator<Item = (&'a AssignedValue<N>, N)> + Clone,
        constant: Option<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let sum = elems
            .clone()
            .map(|(x, y)| x.value().map(|x| x * y))
            .reduce(|acc, x| acc.and_then(|acc| x.map(|x| acc + x)))
            .unwrap();
        let sum = constant.map_or_else(|| sum, |x| sum.map(|sum| sum + x));

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
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::plonk_gate::*;
    use crate::util::test::*;
    use ark_std::{end_timer, start_timer};
    use floor_planner::V1;
    use halo2_proofs::arithmetic::BaseExt;
    use halo2_proofs::circuit::*;
    use halo2_proofs::pairing::bn256::Fr;
    use halo2_proofs::plonk::*;

    #[derive(Clone, Debug)]
    struct TestCircuit {
        is_eq: bool,
    }

    impl Circuit<Fr> for TestCircuit {
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

                    // test sum_with_constant()
                    for i in 1..20 {
                        // gen vars
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

                        if !self.is_eq {
                            sum += Fr::one();
                        }

                        let expect = context.assign(sum)?;
                        let res = context.sum_with_constant(&elems[..], Some(c))?;

                        context.assert_equal(&res, &expect)?;
                    }

                    Ok(())
                },
            )?;
            end_timer!(timer);
            Ok(())
        }
    }

    #[test]
    fn test_native_chip_success() {
        run_circuit_on_bn256(TestCircuit { is_eq: true }, 19);
    }

    #[test]
    fn test_native_chip_fail() {
        run_circuit_on_bn256_expect_fail(TestCircuit { is_eq: false }, 19);
    }
}
