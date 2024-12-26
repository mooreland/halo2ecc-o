use ark_std::iterable::Iterable;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Cell,
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed},
    poly::Rotation,
};
use std::marker::PhantomData;

use crate::{assign::AssignedValue, context::PlonkRegionContext};

pub const VAR_COLUMNS: usize = 5;
pub const MUL_COLUMNS: usize = 2;

#[derive(Clone, Debug)]
pub struct PlonkGateConfig {
    pub var: [Column<Advice>; VAR_COLUMNS],
    pub coeff: [Column<Fixed>; VAR_COLUMNS],
    pub mul_coeff: [Column<Fixed>; MUL_COLUMNS],
    pub next_coeff: Column<Fixed>,
    pub constant: Column<Fixed>,
}

#[derive(Clone, Debug)]
pub struct PlonkGate<N: FieldExt> {
    pub config: PlonkGateConfig,
    mark: PhantomData<N>,
}

impl<N: FieldExt> PlonkGate<N> {
    pub fn new(config: PlonkGateConfig) -> Self {
        Self {
            config,
            mark: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<N>) -> PlonkGateConfig {
        let var = [(); VAR_COLUMNS].map(|_| meta.advice_column());
        let coeff = [(); VAR_COLUMNS].map(|_| meta.fixed_column());
        let mul_coeff = [(); MUL_COLUMNS].map(|_| meta.fixed_column());
        let next_coeff = meta.fixed_column();
        let constant = meta.fixed_column();

        var.iter().for_each(|c| meta.enable_equality(c.clone()));

        meta.create_gate("var_gate", |meta| {
            let _constant = meta.query_fixed(constant, Rotation::cur());
            let _next = meta.query_advice(var[VAR_COLUMNS - 1], Rotation::next());
            let _next_coeff = meta.query_fixed(next_coeff, Rotation::cur());

            let mut acc = _constant + _next * _next_coeff;
            for i in 0..VAR_COLUMNS {
                let _var = meta.query_advice(var[i], Rotation::cur());
                let _coeff = meta.query_fixed(coeff[i], Rotation::cur());
                acc = acc + _var * _coeff;
            }
            for i in 0..MUL_COLUMNS {
                let _var_l = meta.query_advice(var[i * 2], Rotation::cur());
                let _var_r = meta.query_advice(var[i * 2 + 1], Rotation::cur());
                let _mul_coeff = meta.query_fixed(mul_coeff[i], Rotation::cur());
                acc = acc + _var_l * _var_r * _mul_coeff;
            }

            vec![acc]
        });

        PlonkGateConfig {
            var,
            coeff,
            mul_coeff,
            constant,
            next_coeff,
        }
    }
}

pub trait Assigner<N: FieldExt> {
    fn cell(&self) -> Option<Cell>;
    fn value(&self) -> Option<N>;
}

impl<N: FieldExt> Assigner<N> for AssignedValue<N> {
    fn cell(&self) -> Option<Cell> {
        Some(self.cell)
    }

    fn value(&self) -> Option<N> {
        self.value
    }
}

impl<N: FieldExt> Assigner<N> for N {
    fn cell(&self) -> Option<Cell> {
        None
    }

    fn value(&self) -> Option<N> {
        Some(*self)
    }
}

impl<'a, N: FieldExt> Assigner<N> for &'a N {
    fn cell(&self) -> Option<Cell> {
        None
    }

    fn value(&self) -> Option<N> {
        Some(**self)
    }
}

impl<'a, N: FieldExt> PlonkRegionContext<'a, N> {
    pub fn assign_one_line_last_var(
        &mut self,
        value: Option<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let cell = self.region.assign_advice(
            || "",
            self.plonk_gate_config.var[VAR_COLUMNS - 1],
            self.offset,
            || Ok(value.unwrap()),
        )?;
        self.offset += 1;
        Ok(AssignedValue {
            value,
            cell: cell.cell(),
        })
    }

    pub fn assign_one_line<'b>(
        &mut self,
        vars: impl Iterator<Item = (&'b dyn Assigner<N>, N)>,
        constant: Option<N>,
        mul_coeff: impl Iterator<Item = N>,
        next_coeff: Option<N>,
    ) -> Result<[Option<AssignedValue<N>>; VAR_COLUMNS], Error> {
        let mut res = [None; VAR_COLUMNS];

        for (i, (assigner, coeff)) in vars.enumerate() {
            self.region.assign_fixed(
                || "",
                self.plonk_gate_config.coeff[i],
                self.offset,
                || Ok(coeff),
            )?;

            let cell = self.region.assign_advice(
                || "",
                self.plonk_gate_config.var[i],
                self.offset,
                || Ok(assigner.value().unwrap()),
            )?;

            if let Some(assigner_cell) = assigner.cell() {
                self.region.constrain_equal(assigner_cell, cell.cell())?;
            }

            res[i] = Some(AssignedValue {
                value: assigner.value(),
                cell: cell.cell(),
            });
        }

        for (i, coeff) in mul_coeff.enumerate() {
            self.region.assign_fixed(
                || "",
                self.plonk_gate_config.mul_coeff[i],
                self.offset,
                || Ok(coeff),
            )?;
        }

        if let Some(coeff) = next_coeff {
            self.region.assign_fixed(
                || "",
                self.plonk_gate_config.next_coeff,
                self.offset,
                || Ok(coeff),
            )?;
        }

        if let Some(constant) = constant {
            self.region.assign_fixed(
                || "",
                self.plonk_gate_config.constant,
                self.offset,
                || Ok(constant),
            )?;
        }

        self.offset += 1;

        Ok(res)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::util::test::*;
    use ark_std::{end_timer, start_timer};
    use floor_planner::V1;
    use halo2_proofs::arithmetic::BaseExt;
    use halo2_proofs::circuit::*;
    use halo2_proofs::pairing::bn256::Fr;
    use halo2_proofs::plonk::*;

    #[derive(Clone, Debug)]
    struct PlonkTestCircuit {
        diff_at: usize,
        diff_val: Fr,
    }

    impl Circuit<Fr> for PlonkTestCircuit {
        type Config = PlonkGateConfig;
        type FloorPlanner = V1;

        fn configure(meta: &mut ConstraintSystem<Fr>) -> PlonkGateConfig {
            PlonkGate::<Fr>::configure(meta)
        }

        fn without_witnesses(&self) -> Self {
            Self {
                diff_at: 0usize,
                diff_val: Fr::zero(),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let timer = start_timer!(|| "synthesize");
            layouter.assign_region(
                || "range_gate",
                |region| {
                    let mut context = PlonkRegionContext::new(region, &config);

                    for _ in 0..10 {
                        let mut values = [0; VAR_COLUMNS * 2 + MUL_COLUMNS + 2].map(|_| Fr::rand());

                        let mut sum = values
                            .chunks(2)
                            .take(VAR_COLUMNS)
                            .fold(Fr::zero(), |acc, x| acc + x[0] * x[1]);
                        for i in 0..MUL_COLUMNS {
                            sum += values[i * 4] * values[i * 4 + 2] * values[VAR_COLUMNS * 2 + i];
                        }
                        sum += values[VAR_COLUMNS * 2 + MUL_COLUMNS]
                            * values[VAR_COLUMNS * 2 + MUL_COLUMNS + 1];

                        values[self.diff_at] += self.diff_val;

                        context.assign_one_line(
                            values
                                .chunks(2)
                                .take(VAR_COLUMNS)
                                .map(|x| (&x[0] as _, x[1])),
                            Some(-sum),
                            values.iter().skip(VAR_COLUMNS * 2).take(MUL_COLUMNS),
                            Some(values[VAR_COLUMNS * 2 + MUL_COLUMNS]),
                        )?;

                        context.assign_one_line_last_var(Some(
                            values[VAR_COLUMNS * 2 + MUL_COLUMNS + 1],
                        ))?;
                    }

                    Ok(())
                },
            )?;
            end_timer!(timer);
            Ok(())
        }
    }

    #[test]
    fn test_range_gate_success() {
        run_circuit_on_bn256(
            PlonkTestCircuit {
                diff_at: 0,
                diff_val: Fr::zero(),
            },
            19,
        );
    }

    #[test]
    fn test_range_gate_fail() {
        for i in 0..VAR_COLUMNS * 2 + MUL_COLUMNS + 2 {
            run_circuit_on_bn256_expect_fail(
                PlonkTestCircuit {
                    diff_at: i,
                    diff_val: Fr::one(),
                },
                19,
            );
        }
    }
}
