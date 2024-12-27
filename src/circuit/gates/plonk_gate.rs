use ark_std::iterable::Iterable;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Cell,
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed},
    poly::Rotation,
};
use std::marker::PhantomData;

use crate::{
    assign::{AssignedValue, MayAssignedValue},
    context::PlonkRegionContext,
};

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

impl<'a, N: FieldExt> PlonkRegionContext<'a, N> {
    pub fn assign_one_line_last_var(
        &mut self,
        value: MayAssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let cells = self.assign_one_line(&[], Some(value), None, &[], None)?;

        Ok(cells[VAR_COLUMNS - 1].unwrap())
    }

    pub fn assign_one_line<'b>(
        &mut self,
        vars: &[(MayAssignedValue<N>, N)],
        last_var: Option<MayAssignedValue<N>>,
        constant: Option<N>,
        mul_coeff: &[N],
        next_coeff: Option<N>,
    ) -> Result<[Option<AssignedValue<N>>; VAR_COLUMNS], Error> {
        let mut res = [None; VAR_COLUMNS];

        for (i, (assigner, coeff)) in vars.into_iter().enumerate() {
            self.region.assign_fixed(
                || "",
                self.plonk_gate_config.coeff[i],
                self.offset,
                || Ok(*coeff),
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

        if let Some(last_var) = last_var {
            let cell = self.region.assign_advice(
                || "",
                self.plonk_gate_config.var[VAR_COLUMNS - 1],
                self.offset,
                || Ok(last_var.value().unwrap()),
            )?;

            if let Some(assigner_cell) = last_var.cell() {
                self.region.constrain_equal(assigner_cell, cell.cell())?;
            }

            res[VAR_COLUMNS - 1] = Some(AssignedValue {
                value: last_var.value(),
                cell: cell.cell(),
            });
        }

        for (i, coeff) in mul_coeff.into_iter().enumerate() {
            self.region.assign_fixed(
                || "",
                self.plonk_gate_config.mul_coeff[i],
                self.offset,
                || Ok(*coeff),
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
        vars: [Option<Fr>; VAR_COLUMNS + 1],
        coeffs: [Fr; VAR_COLUMNS + MUL_COLUMNS + 1],
        sum: Fr,
    }

    impl Circuit<Fr> for PlonkTestCircuit {
        type Config = PlonkGateConfig;
        type FloorPlanner = V1;

        fn configure(meta: &mut ConstraintSystem<Fr>) -> PlonkGateConfig {
            PlonkGate::<Fr>::configure(meta)
        }

        fn without_witnesses(&self) -> Self {
            Self {
                vars: [None; VAR_COLUMNS + 1],
                coeffs: self.coeffs.clone(),
                sum: self.sum,
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

                    let timer = start_timer!(|| "assign_one_line");
                    for _ in 0..1 {
                        //(1 << 19) - 30 {
                        context.assign_one_line(
                            &self
                                .vars
                                .iter()
                                .zip(self.coeffs.iter())
                                .take(VAR_COLUMNS)
                                .map(|(v, c)| (v.into(), c))
                                .collect::<Vec<_>>(),
                            None,
                            Some(-self.sum),
                            &self.coeffs[VAR_COLUMNS..VAR_COLUMNS + MUL_COLUMNS],
                            Some(self.coeffs[VAR_COLUMNS + MUL_COLUMNS]),
                        )?;

                        context.assign_one_line_last_var((&self.vars[VAR_COLUMNS]).into())?;
                    }
                    end_timer!(timer);

                    Ok(())
                },
            )?;
            end_timer!(timer);
            Ok(())
        }
    }

    fn gen_random_plonk_gate_test_circuit() -> PlonkTestCircuit {
        let vars = [0; VAR_COLUMNS + 1].map(|_| Fr::rand());
        let coeffs = [0; VAR_COLUMNS + MUL_COLUMNS + 1].map(|_| Fr::rand());

        let mut sum = vars
            .iter()
            .zip(coeffs.iter())
            .take(VAR_COLUMNS)
            .fold(Fr::zero(), |acc, x| acc + x.0 * x.1);

        for i in 0..MUL_COLUMNS {
            sum += vars[i * 2] * vars[i * 2 + 1] * coeffs[VAR_COLUMNS + i];
        }

        sum += vars[VAR_COLUMNS] * coeffs[VAR_COLUMNS + MUL_COLUMNS];

        PlonkTestCircuit {
            vars: vars.map(|x| Some(x)),
            coeffs,
            sum,
        }
    }

    #[test]
    fn bench_plonk_gate() {
        bench_circuit_on_bn256(gen_random_plonk_gate_test_circuit(), 20);
    }

    #[test]
    fn test_plonk_gate_success() {
        run_circuit_on_bn256(gen_random_plonk_gate_test_circuit(), 20);
    }

    #[test]
    fn test_plonk_gate_fail() {
        for i in 0..VAR_COLUMNS + 1 {
            let mut circuit = gen_random_plonk_gate_test_circuit();
            circuit.vars[i].as_mut().map(|x| *x += Fr::one());

            run_circuit_on_bn256_expect_fail(circuit, 20);
        }
    }
}
