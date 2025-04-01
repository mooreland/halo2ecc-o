use ark_std::end_timer;
use ark_std::start_timer;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::pairing::group::ff::PrimeField;
use halo2_proofs::pairing::group::Curve;
use halo2_proofs::plonk::Error;
use num_integer::Integer;

use crate::assign::*;
use crate::chips::ecc_chip::EccChipBaseOps;
use crate::chips::native_chip::NativeChipOps;
use crate::context::*;
use crate::pair;
use crate::utils::*;

use super::bit_chip::BitChipOps;
use super::ecc_chip::EccUnsafeError;

pub const MSM_PREFIX_OFFSET: u64 = 1 << 16;

impl<'b, C: CurveAffine> EccChipMSMOps<'b, C, C::Scalar> for NativeScalarEccContext<'b, C> {
    type AssignedScalar = AssignedValue<C::Scalar>;

    fn get_and_increase_msm_prefix(&mut self) -> u64 {
        let msm_index = self.msm_index;
        self.msm_index += 1;
        msm_index * MSM_PREFIX_OFFSET
    }

    fn decompose_scalar<const WINDOW_SIZE: usize>(
        &mut self,
        s: &Self::AssignedScalar,
    ) -> Result<Vec<[AssignedCondition<C::Scalar>; WINDOW_SIZE]>, Error> {
        let one = C::Scalar::one();
        let two = one + &one;
        let four = two + &two;

        let mut bits = vec![];

        //TODO: replace with option
        let s_bn = field_to_bn(&s.value().unwrap_or(C::Scalar::zero()));
        let mut v = s.clone();

        for i in 0..<C::ScalarExt as PrimeField>::NUM_BITS as u64 / 2 {
            let b0 = if s_bn.bit(i * 2) {
                C::ScalarExt::one()
            } else {
                C::ScalarExt::zero()
            };
            let b1 = if s_bn.bit(i * 2 + 1) {
                C::ScalarExt::one()
            } else {
                C::ScalarExt::zero()
            };
            let b0 = self.plonk_region_context().assign_bit(b0)?;
            let b1 = self.plonk_region_context().assign_bit(b1)?;
            let v_next: C::ScalarExt = bn_to_field(&(&s_bn >> (i * 2 + 2)));

            let cells = self.plonk_region_context().one_line(
                [
                    pair!(&v_next, four),
                    pair!(b1.as_ref(), two),
                    pair!(b0.as_ref(), one),
                    pair!(&v, -one),
                ]
                .into_iter(),
                None,
                ([], None),
            )?;

            v = cells[0].unwrap();

            bits.push(b0);
            bits.push(b1);
        }

        if <C::ScalarExt as PrimeField>::NUM_BITS.is_odd() {
            self.plonk_region_context().assert_bit(&v)?;
            bits.push(v.into());
        } else {
            self.plonk_region_context()
                .assert_equal_constant(&v, C::Scalar::zero())?;
        }

        let rem = <C::ScalarExt as PrimeField>::NUM_BITS as usize % WINDOW_SIZE;
        if rem > 0 {
            let zero = self
                .plonk_region_context()
                .assign_constant(C::ScalarExt::zero())?;
            for _ in 0..WINDOW_SIZE - rem {
                bits.push(zero.into());
            }
        }

        let mut res: Vec<_> = bits
            .chunks(WINDOW_SIZE)
            .into_iter()
            .map(|x| x.try_into().unwrap())
            .collect();
        res.reverse();

        Ok(res)
    }

    fn ecc_bisec_scalar(
        &mut self,
        cond: &AssignedCondition<C::Scalar>,
        a: &Self::AssignedScalar,
        b: &Self::AssignedScalar,
    ) -> Result<Self::AssignedScalar, Error> {
        self.plonk_region_context().bisec(cond, a, b)
    }

    fn ecc_assign_constant_zero_scalar(&mut self) -> Result<Self::AssignedScalar, Error> {
        self.plonk_region_context()
            .assign_constant(C::Scalar::zero())
    }
}

impl<'b, C: CurveAffine, N: FieldExt> EccChipMSMOps<'b, C, N>
    for GeneralScalarEccContext<'b, C, N>
{
    type AssignedScalar = AssignedInteger<C::Scalar, N>;

    fn get_and_increase_msm_prefix(&mut self) -> u64 {
        let msm_index = self.msm_index;
        self.msm_index += 1;
        msm_index * MSM_PREFIX_OFFSET
    }

    fn decompose_scalar<const WINDOW_SIZE: usize>(
        &mut self,
        s: &Self::AssignedScalar,
    ) -> Result<Vec<[AssignedCondition<N>; WINDOW_SIZE]>, Error> {
        let zero = N::zero();
        let one = N::one();
        let two = one + one;
        let two_inv = two.invert().unwrap();

        let s = self.scalar_integer_context.reduce(&s)?;
        let mut bits = vec![];

        for l in s.limbs_le {
            let lv = l.unwrap();
            let v = field_to_bn(&lv.value().unwrap());
            let mut rest = lv;
            for j in 0..self.scalar_integer_context.info.limb_bits {
                let b = self
                    .get_plonk_region_context()
                    .assign_bit(v.bit(j).into())
                    .unwrap();
                let v = (rest.value().unwrap() - b.value().unwrap()) * two_inv;
                rest = self
                    .get_plonk_region_context()
                    .one_line_with_last(
                        vec![pair!(&rest, -one), pair!(&AssignedValue::from(b), one)].into_iter(),
                        pair!(&v, two),
                        None,
                        ([], None),
                    )?
                    .1;
                bits.push(b);
            }

            self.get_plonk_region_context()
                .assert_equal_constant(&rest, zero)?
        }

        let padding = bits.len() % WINDOW_SIZE;
        if padding != 0 {
            let zero = self.get_plonk_region_context().assign_constant(zero)?;
            for _ in padding..WINDOW_SIZE {
                bits.push(AssignedCondition::from(zero));
            }
        }
        assert!(bits.len() % WINDOW_SIZE == 0);

        let mut res = bits
            .chunks_exact(WINDOW_SIZE)
            .map(|x| Vec::from(x).try_into().unwrap())
            .collect::<Vec<_>>();

        res.reverse();

        Ok(res)
    }

    fn ecc_bisec_scalar(
        &mut self,
        cond: &AssignedCondition<N>,
        a: &Self::AssignedScalar,
        b: &Self::AssignedScalar,
    ) -> Result<Self::AssignedScalar, Error> {
        self.scalar_integer_context.bisec_int(cond, a, b)
    }

    fn ecc_assign_constant_zero_scalar(&mut self) -> Result<Self::AssignedScalar, Error> {
        self.scalar_integer_context
            .assign_int_constant(C::Scalar::zero())
    }
}

pub trait EccChipMSMOps<'a, C: CurveAffine, N: FieldExt>:
    EccChipBaseOps<'a, C, N> + ParallelClone + Send + Sized
{
    type AssignedScalar: Clone + Sync;

    fn get_and_increase_msm_prefix(&mut self) -> u64;

    fn decompose_scalar<const WINDOW_SIZE: usize>(
        &mut self,
        s: &Self::AssignedScalar,
    ) -> Result<Vec<[AssignedCondition<N>; WINDOW_SIZE]>, Error>;

    fn msm_batch_on_group_non_zero_with_select_chip(
        &mut self,
        points: &Vec<AssignedNonZeroPoint<C, N>>,
        scalars: &Vec<Self::AssignedScalar>,
        rand_acc_point: C,
        rand_line_point: C,
    ) -> Result<AssignedPoint<C, N>, EccUnsafeError> {
        assert!(points.len() as u64 <= MSM_PREFIX_OFFSET);

        // Reduce points for parallel setup optimization.
        let points = points
            .iter()
            .map(|p| self.ecc_reduce_non_zero(p))
            .collect::<Result<Vec<_>, _>>()?;

        let rand_acc_point = self.assign_non_zero_point(Some(rand_acc_point))?;
        let rand_line_point = self.assign_non_zero_point(Some(rand_line_point))?;

        let rand_acc_point_neg = self.ecc_neg_non_zero(&rand_acc_point)?;
        let rand_acc_point_neg = self.ecc_reduce_non_zero(&rand_acc_point_neg)?;
        let rand_line_point_neg = self.ecc_neg_non_zero(&rand_line_point)?;
        let rand_line_point_neg = self.ecc_reduce_non_zero(&rand_line_point_neg)?;

        let best_group_size = 6;
        let n_group = (points.len() + best_group_size - 1) / best_group_size;
        let group_size = (points.len() + n_group - 1) / n_group;

        let mut constants = vec![];
        {
            let mut v = N::zero();
            for _ in 0..1 << group_size {
                constants.push(self.plonk_region_context().assign_constant(v)?);
                v += N::one();
            }
        }

        // Prepare candidation points for each group.
        let group_prefix = self.get_and_increase_msm_prefix();

        let groups = points.chunks(group_size).collect::<Vec<_>>();
        let candidates = self.do_parallel(
            |op, group_index| -> Result<Vec<AssignedNonZeroPoint<C, N>>, EccUnsafeError> {
                let mut res = vec![];

                let init = if group_index.is_even() {
                    &rand_line_point
                } else {
                    &rand_line_point_neg
                };

                res.push(init.clone());
                op.kvmap_set_ecc_non_zero(group_prefix + group_index as u64, &constants[0], &init)?;

                for i in 1..1u32 << groups[group_index].len() {
                    let pos = i.reverse_bits().leading_zeros(); // find the last bit-1 position
                    let other = i - (1 << pos);
                    let p = op
                        .ecc_add_unsafe(&res[other as usize], &groups[group_index][pos as usize])?;
                    let p = op.ecc_reduce_non_zero(&p)?;

                    op.kvmap_set_ecc_non_zero(
                        group_prefix + group_index as u64,
                        &constants[i as usize],
                        &p,
                    )?;
                    res.push(p);
                }

                Ok(res)
            },
            groups.len(),
        )?;

        // Decompose to get bits of each (window, group).
        let bits = self.do_parallel(
            |op, i| -> Result<_, Error> {
                let res = op.decompose_scalar::<1>(&scalars[i])?;
                Ok(res)
            },
            scalars.len(),
        )?;

        let groups = bits.chunks(group_size).collect::<Vec<_>>();

        // Accumulate points of all groups in each window.
        let windows = bits[0].len();

        let line_acc_arr = self.do_parallel(
            |op, wi| -> Result<_, EccUnsafeError> {
                let mut acc = rand_acc_point_neg.clone();
                for group_index in 0..groups.len() {
                    let group_bits = groups[group_index].iter().map(|bits| bits[wi][0]).collect();
                    let (index_cell, ci) =
                        op.pick_candidate_non_zero(&candidates[group_index], &group_bits)?;
                    let ci = op.kvmap_get_ecc_non_zero(
                        group_index as u64 + group_prefix,
                        &index_cell,
                        &ci,
                    )?;

                    acc = op.ecc_add_unsafe(&ci, &acc)?;
                }
                Ok(acc)
            },
            windows,
        )?;

        // Accumulate points of all windows.
        let mut acc = rand_acc_point.clone();
        for wi in 0..windows {
            acc = self.ecc_double_unsafe(&acc)?;
            acc = self.ecc_add_unsafe(&line_acc_arr[wi], &acc)?;
            if groups.len().is_odd() {
                acc = self.ecc_add_unsafe(&acc, &rand_line_point_neg)?;
            }
        }

        // downgrade before add in case that result is identity
        let acc = self.ecc_non_zero_point_downgrade(&acc)?;
        let carry = self.ecc_non_zero_point_downgrade(&rand_acc_point_neg)?;
        let res = self.ecc_add(&acc, &carry)?;

        Ok(res)
    }

    fn msm_unsafe(
        &mut self,
        points: &Vec<AssignedPoint<C, N>>,
        scalars: &Vec<Self::AssignedScalar>,
    ) -> Result<AssignedPoint<C, N>, EccUnsafeError> {
        let r1 = (C::generator() * C::Scalar::rand()).to_affine();
        let r2 = (C::generator() * C::Scalar::rand()).to_affine();

        let mut non_zero_points = vec![];
        let mut normalized_scalars = vec![];
        let non_zero_p = self.assign_non_zero_point(Some(C::generator()))?;
        let s_zero = self.ecc_assign_constant_zero_scalar()?;

        for (p, s) in points.iter().zip(scalars.iter()) {
            let s = self.ecc_bisec_scalar(&p.z, &s_zero, s)?;
            let p = self.ecc_bisec_to_non_zero_point(p, &non_zero_p)?;
            non_zero_points.push(p);
            normalized_scalars.push(s);
        }

        let timer = start_timer!(|| "msm_batch_on_group_non_zero_with_select_chip");
        let p = self.msm_batch_on_group_non_zero_with_select_chip(
            &non_zero_points,
            &normalized_scalars,
            r1,
            r2,
        )?;
        end_timer!(timer);

        Ok(p)
    }

    fn msm(
        &mut self,
        points: &Vec<AssignedPoint<C, N>>,
        scalars: &Vec<Self::AssignedScalar>,
    ) -> Result<AssignedPoint<C, N>, EccUnsafeError> {
        self.msm_unsafe(points, scalars)
    }

    fn ecc_mul(&mut self, a: &AssignedPoint<C, N>, s: Self::AssignedScalar) -> AssignedPoint<C, N> {
        self.msm_unsafe(&vec![a.clone()], &vec![s.clone()]).unwrap()
    }

    fn ecc_bisec_scalar(
        &mut self,
        cond: &AssignedCondition<N>,
        a: &Self::AssignedScalar,
        b: &Self::AssignedScalar,
    ) -> Result<Self::AssignedScalar, Error>;

    fn ecc_assign_constant_zero_scalar(&mut self) -> Result<Self::AssignedScalar, Error>;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::chips::msm_chip::EccChipMSMOps;
    use crate::chips::msm_chip::ParallelClone;
    use crate::utils::test::*;
    use crate::NativeScalarEccConfig;
    use ark_std::{end_timer, start_timer};
    use floor_planner::FlatFloorPlanner;
    use halo2_proofs::arithmetic::BaseExt;
    use halo2_proofs::circuit::*;
    use halo2_proofs::pairing::bn256::Fr;
    use halo2_proofs::pairing::bn256::G1Affine;
    use halo2_proofs::pairing::group::cofactor::CofactorCurveAffine;
    use halo2_proofs::plonk::*;
    use rand_core::OsRng;

    #[derive(Clone, Debug)]
    struct TestCircuit<
        F: Clone + Fn(&mut NativeScalarEccContext<'_, G1Affine>) -> Result<(), Error>,
    > {
        fill: F,
    }

    impl<F: Clone + Fn(&mut NativeScalarEccContext<'_, G1Affine>) -> Result<(), Error>> Circuit<Fr>
        for TestCircuit<F>
    {
        type Config = NativeScalarEccConfig;
        type FloorPlanner = FlatFloorPlanner;

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            NativeScalarEccConfig::configure::<G1Affine>(meta)
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
                    let mut native_ecc_context = config.to_context(region);

                    native_ecc_context
                        .integer_context
                        .range_region_context
                        .init()?;
                    (self.fill)(&mut native_ecc_context)?;

                    let timer = start_timer!(|| "finalize_int_mul");
                    native_ecc_context.integer_context.finalize_int_mul()?;
                    end_timer!(timer);

                    let timer = start_timer!(|| "finalize_compact_cells");
                    native_ecc_context
                        .integer_context
                        .range_region_context
                        .finalize_compact_cells()?;
                    end_timer!(timer);

                    Ok(())
                },
            )?;
            end_timer!(timer);
            Ok(())
        }
    }

    fn fill_msm_test(
        context: &mut NativeScalarEccContext<'_, G1Affine>,
        is_success: bool,
    ) -> Result<(), Error> {
        if is_success {
            let mut points = vec![];
            let mut scalars = vec![];

            let mut acc = G1Affine::identity().to_curve();
            for _ in 0..10 {
                let p = G1Affine::random(OsRng);
                let s = Fr::rand();
                points.push(context.assign_point(Some(p))?);
                scalars.push(context.plonk_region_context().assign(s)?);
                acc = acc + p * s;
            }

            let timer = start_timer!(|| "msm");
            let p = context.msm(&points, &scalars).unwrap();
            end_timer!(timer);

            let assigned_acc = context.assign_point(Some(acc.to_affine()))?;
            context.ecc_assert_equal(&p, &assigned_acc)?;

            println!("offset is {:?}", context.offset());
        } else {
            unimplemented!()
        }
        Ok(())
    }

    #[test]
    fn test_msm_chip_success() {
        run_circuit_on_bn256(
            TestCircuit {
                fill: |context| {
                    let is_success = true;

                    for v in [fill_msm_test] {
                        v(context, is_success)?;
                    }

                    Ok(())
                },
            },
            22,
        );
    }

    #[test]
    #[cfg(feature = "profile")]
    fn bench_msm_chip_success() {
        bench_circuit_on_bn256(
            TestCircuit {
                fill: |context| {
                    let is_success = true;

                    for v in [fill_msm_test] {
                        v(context, is_success)?;
                    }

                    Ok(())
                },
            },
            19,
        );
    }

    /*
    #[test]
    fn test_int_chip_fail1() {
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
                fill_msm_test
            ] {
                test_fail!(v);
            }
        }
    }
    */
}
