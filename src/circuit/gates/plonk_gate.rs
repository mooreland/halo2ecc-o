use ark_std::iterable::Iterable;
use halo2_proofs::{
    arithmetic::FieldExt,
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

impl<'a, N: FieldExt> PlonkRegionContext<'a, N> {
    pub fn assign_one_line_last_var(
        &mut self,
        value: MayAssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let cells = self.assign_one_line(&[], Some((value, N::zero())), None, &[], None)?;

        Ok(cells[VAR_COLUMNS - 1].unwrap())
    }

    pub fn assign_one_line<'b>(
        &mut self,
        var_coeff_pairs: &[(MayAssignedValue<N>, N)],
        last_var_pair: Option<(MayAssignedValue<N>, N)>,
        constant: Option<N>,
        mul_coeff: &[N],
        next_coeff: Option<N>,
    ) -> Result<[Option<AssignedValue<N>>; VAR_COLUMNS], Error> {
        let mut res = [None; VAR_COLUMNS];

        for (i, (assigner, coeff)) in var_coeff_pairs.into_iter().enumerate() {
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

        if let Some((last_var, coeff)) = last_var_pair {
            self.region.assign_fixed(
                || "",
                self.plonk_gate_config.coeff[VAR_COLUMNS - 1],
                self.offset,
                || Ok(coeff),
            )?;

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
        k: usize,
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
                k: self.k,
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
                    let adv_test_cell = region.assign_advice(
                        || "assign sum",
                        config.var[0],
                        (1 << self.k) - 30,
                        || Ok(Fr::zero()),
                    )?;

                    let fix_test_cell = region.assign_fixed(
                        || "assign sum",
                        config.coeff[0],
                        (1 << self.k) - 30,
                        || Ok(Fr::zero()),
                    )?;

                    // Skip shape stage
                    if adv_test_cell.value().is_none() && fix_test_cell.value().is_none() {
                        return Ok(());
                    }

                    std::thread::scope(|s| {
                        let timer = start_timer!(|| "assign_one_line");
                        let size = (1 << (self.k - 1)) - 30;
                        let threads = 32;
                        let size_per_thread = size / threads;
                        let mut tasks = vec![];
                        for i in 0..threads {
                            let _region = region.clone();
                            let config = config.clone();
                            let t = s.spawn(move || {
                                let region = _region;
                                let mut context = PlonkRegionContext::new(&region, &config);
                                context.set_offset(size_per_thread * i * 2);
                                let start = size_per_thread * i;
                                let end = size.min(size_per_thread * (i + 1));
                                for _ in start..end {
                                    context
                                        .assign_one_line(
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
                                        )
                                        .unwrap();

                                    context
                                        .assign_one_line_last_var((&self.vars[VAR_COLUMNS]).into())
                                        .unwrap();
                                }
                            });
                            tasks.push(t);
                        }
                        for t in tasks {
                            t.join().unwrap();
                        }
                        end_timer!(timer);
                    });
                    Ok(())
                },
            )?;

            end_timer!(timer);
            Ok(())
        }
    }

    fn gen_random_plonk_gate_test_circuit(k: usize) -> PlonkTestCircuit {
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
            k,
        }
    }

    #[test]
    fn bench_plonk_gate() {
        bench_circuit_on_bn256(gen_random_plonk_gate_test_circuit(20), 20);
    }

    #[test]
    fn test_plonk_gate_success() {
        run_circuit_on_bn256(gen_random_plonk_gate_test_circuit(8), 19);
    }

    #[test]
    fn test_plonk_gate_fail() {
        for i in 0..VAR_COLUMNS + 1 {
            let mut circuit = gen_random_plonk_gate_test_circuit(8);
            circuit.vars[i].as_mut().map(|x| *x += Fr::one());

            run_circuit_on_bn256_expect_fail(circuit, 19);
        }
    }
}
