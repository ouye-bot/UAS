use crate::util::{
    arithmetic::{Field, PrimeField},
    expression::{CommonPolynomial, Expression, Query, Rotation},
};
use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::Debug,
    ops::Deref,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct ExpressionRegistry<F: Field> {
    offsets: Offsets,
    constants: Vec<F>,
    has_identity: bool,
    lagranges: Vec<i32>,
    eq_xys: Vec<usize>,
    rotations: Vec<Rotation>,
    polys: Vec<(Query, usize)>,
    calculations: Vec<Calculation<ValueSource>>,
    indexed_calculations: Vec<Calculation<usize>>,
    outputs: Vec<ValueSource>,
    indexed_outputs: Vec<usize>,
    // ── O(1) dedup indices (root-fix 2026-08-27) ──
    //
    // register_value used to answer every "have I seen this item?" with a
    // LINEAR position() scan over the corresponding vec. For flat flat-constraint
    // compositions the simplified zero-check expression yields hundreds of
    // thousands of calculations, so registration cost was O(#calcs^2)
    // comparisons -- a single-core stall of minutes-to-hours BEFORE round 0
    // (measured live: probe wedged >4 min inside [sce] simplified-done..
    // registered on a pegged core, memory flat). The vecs keep their exact
    // insertion order and content; these maps only memoize first-insertion
    // positions, so all downstream indexing is unchanged.
    constants_index: HashMap<Box<[u8]>, usize>,
    lagranges_index: HashMap<i32, usize>,
    eq_xys_index: HashMap<usize, usize>,
    rotations_index: HashMap<Rotation, usize>,
    polys_index: HashMap<(Query, usize), usize>,
    calculations_index: HashMap<Calculation<ValueSource>, usize>,
}

/// Diagnostic-only counter for registration progress heartbeats (feature
/// "timer"): incremented once per registered calculation.
#[cfg(feature = "timer")]
static REG_HEARTBEAT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

// PrimeField is required only so constants can hash by `to_repr` bytes.
impl<F: Field + PrimeField> ExpressionRegistry<F> {
    pub(crate) fn new() -> Self {
        Self {
            constants: vec![F::ZERO, F::ONE, F::ONE.double()],
            rotations: vec![Rotation(0)],
            ..Default::default()
        }
    }

    pub(crate) fn register(&mut self, expression: &Expression<F>) {
        let output = self.register_expression(expression);
        self.offsets = Offsets::new(
            self.constants.len(),
            self.lagranges.len(),
            self.eq_xys.len(),
            self.polys.len(),
        );
        self.indexed_calculations = self
            .calculations
            .iter()
            .map(|calculation| calculation.indexed(&self.offsets))
            .collect();
        self.outputs.push(output);
        self.indexed_outputs = self
            .outputs
            .iter()
            .map(|output| output.indexed(&self.offsets))
            .collect();
        // Diagnostic-only (feature "timer"): registry scale probe. Note the
        // dedup path above (register_value) is a LINEAR scan over these vecs,
        // so registration cost is O(#calcs ^ 2) -- this line quantifies why a
        // large flat constraint sum stalls before round 0 ever starts.
        #[cfg(feature = "timer")]
        eprintln!(
            "[registry] rotations={} lagranges={} eq_xys={} polys={} calcs={} ",
            self.rotations.len(),
            self.lagranges.len(),
            self.eq_xys.len(),
            self.polys.len(),
            self.calculations.len()
        );
    }

    pub(crate) fn offsets(&self) -> &Offsets {
        &self.offsets
    }

    pub(crate) fn has_identity(&self) -> bool {
        self.has_identity
    }

    pub(crate) fn lagranges(&self) -> &[i32] {
        &self.lagranges
    }

    pub(crate) fn eq_xys(&self) -> &[usize] {
        &self.eq_xys
    }

    pub(crate) fn rotations(&self) -> &[Rotation] {
        &self.rotations
    }

    pub(crate) fn polys(&self) -> &[(Query, usize)] {
        &self.polys
    }

    pub(crate) fn indexed_calculations(&self) -> &[Calculation<usize>] {
        &self.indexed_calculations
    }

    pub(crate) fn indexed_outputs(&self) -> &[usize] {
        &self.indexed_outputs
    }

    pub(crate) fn cache(&self) -> Vec<F> {
        let mut cache = vec![F::ZERO; self.offsets.calculations() + self.calculations.len()];
        cache[..self.constants.len()].clone_from_slice(&self.constants);
        cache
    }

    // ── Dedup via the memo maps; vec order/content identical to the era of
    // linear scans (root-fix 2026-08-27, see struct docs) ──

    fn register_constant(&mut self, constant: &F) -> ValueSource {
        // Field elements hash by canonical repr bytes (`to_repr`); this keeps
        // `constants_index` keyable without a Hash bound on the abstract
        // ff::Field trait. Equality-by-repr == equality-by-value for the
        // canonical forms these types carry.
        let next = self.constants.len();
        let key = Box::<[u8]>::from(constant.to_repr().as_ref());
        match self.constants_index.entry(key) {
            Entry::Occupied(entry) => ValueSource::Constant(*entry.get()),
            Entry::Vacant(entry) => {
                entry.insert(next);
                self.constants.push(constant.clone());
                ValueSource::Constant(next)
            }
        }
    }

    fn register_identity(&mut self) -> ValueSource {
        self.has_identity = true;
        ValueSource::Identity
    }

    fn register_lagrange(&mut self, i: i32) -> ValueSource {
        let next = self.lagranges.len();
        match self.lagranges_index.entry(i) {
            Entry::Occupied(entry) => ValueSource::Lagrange(*entry.get()),
            Entry::Vacant(entry) => {
                entry.insert(next);
                self.lagranges.push(i);
                ValueSource::Lagrange(next)
            }
        }
    }

    fn register_eq_xy(&mut self, idx: usize) -> ValueSource {
        let next = self.eq_xys.len();
        match self.eq_xys_index.entry(idx) {
            Entry::Occupied(entry) => ValueSource::EqXY(*entry.get()),
            Entry::Vacant(entry) => {
                entry.insert(next);
                self.eq_xys.push(idx);
                ValueSource::EqXY(next)
            }
        }
    }

    fn register_rotation(&mut self, rotation: Rotation) -> usize {
        let next = self.rotations.len();
        match self.rotations_index.entry(rotation) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                entry.insert(next);
                self.rotations.push(rotation);
                next
            }
        }
    }

    fn register_poly(&mut self, query: &Query) -> ValueSource {
        let rotation = self.register_rotation(query.rotation());
        let next = self.polys.len();
        match self.polys_index.entry((*query, rotation)) {
            Entry::Occupied(entry) => ValueSource::Poly(*entry.get()),
            Entry::Vacant(entry) => {
                entry.insert(next);
                self.polys.push((*query, rotation));
                ValueSource::Poly(next)
            }
        }
    }

    fn register_calculation(&mut self, calculation: Calculation<ValueSource>) -> ValueSource {
        #[cfg(feature = "timer")]
        {
            let n = REG_HEARTBEAT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n & ((1 << 21) - 1) == 0 && n > 0 {
                eprintln!("[registry-heartbeat] calc#{n}");
            }
        }
        let next = self.calculations.len();
        if let Some(idx) = self.calculations_index.get(&calculation) {
            return ValueSource::Calculation(*idx);
        }
        self.calculations_index.insert(calculation.clone(), next);
        self.calculations.push(calculation);
        ValueSource::Calculation(next)
    }

    fn register_expression(&mut self, expr: &Expression<F>) -> ValueSource {
        match expr {
            Expression::Constant(constant) => self.register_constant(constant),
            Expression::CommonPolynomial(poly) => match poly {
                CommonPolynomial::Identity => self.register_identity(),
                CommonPolynomial::Lagrange(i) => self.register_lagrange(*i),
                CommonPolynomial::EqXY(idx) => self.register_eq_xy(*idx),
            },
            Expression::Polynomial(query) => self.register_poly(query),
            Expression::Challenge(_) => unreachable!(),
            Expression::Negated(value) => {
                if let Expression::Constant(constant) = value.deref() {
                    self.register_constant(&-*constant)
                } else {
                    let value = self.register_expression(value);
                    if let ValueSource::Constant(idx) = value {
                        self.register_constant(&-self.constants[idx])
                    } else {
                        self.register_calculation(Calculation::Negated(value))
                    }
                }
            }
            Expression::Sum(lhs, rhs) => match (lhs.deref(), rhs.deref()) {
                (minuend, Expression::Negated(subtrahend))
                | (Expression::Negated(subtrahend), minuend) => {
                    let minuend = self.register_expression(minuend);
                    let subtrahend = self.register_expression(subtrahend);
                    match (minuend, subtrahend) {
                        (ValueSource::Constant(minuend), ValueSource::Constant(subtrahend)) => self
                            .register_constant(
                                &(self.constants[minuend] - &self.constants[subtrahend]),
                            ),
                        (ValueSource::Constant(0), _) => {
                            self.register_calculation(Calculation::Negated(subtrahend))
                        }
                        (_, ValueSource::Constant(0)) => minuend,
                        _ => self.register_calculation(Calculation::Sub(minuend, subtrahend)),
                    }
                }
                _ => {
                    let lhs = self.register_expression(lhs);
                    let rhs = self.register_expression(rhs);
                    match (lhs, rhs) {
                        (ValueSource::Constant(lhs), ValueSource::Constant(rhs)) => {
                            self.register_constant(&(self.constants[lhs] + &self.constants[rhs]))
                        }
                        (ValueSource::Constant(0), other) | (other, ValueSource::Constant(0)) => {
                            other
                        }
                        _ => {
                            if lhs <= rhs {
                                self.register_calculation(Calculation::Add(lhs, rhs))
                            } else {
                                self.register_calculation(Calculation::Add(rhs, lhs))
                            }
                        }
                    }
                }
            },
            Expression::Product(lhs, rhs) => {
                let lhs = self.register_expression(lhs);
                let rhs = self.register_expression(rhs);
                match (lhs, rhs) {
                    (ValueSource::Constant(0), _) | (_, ValueSource::Constant(0)) => {
                        ValueSource::Constant(0)
                    }
                    (ValueSource::Constant(1), other) | (other, ValueSource::Constant(1)) => other,
                    (ValueSource::Constant(2), other) | (other, ValueSource::Constant(2)) => {
                        self.register_calculation(Calculation::Add(other, other))
                    }
                    (lhs, rhs) => {
                        if lhs <= rhs {
                            self.register_calculation(Calculation::Mul(lhs, rhs))
                        } else {
                            self.register_calculation(Calculation::Mul(rhs, lhs))
                        }
                    }
                }
            }
            Expression::Scaled(value, scalar) => {
                if scalar == &F::ZERO {
                    ValueSource::Constant(0)
                } else if scalar == &F::ONE {
                    self.register_expression(value)
                } else {
                    let value = self.register_expression(value);
                    let scalar = self.register_constant(scalar);
                    self.register_calculation(Calculation::Mul(value, scalar))
                }
            }
            Expression::DistributePowers(_, _) => unreachable!(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Offsets(usize, usize, usize, usize, usize);

impl Offsets {
    fn new(
        num_constants: usize,
        num_lagranges: usize,
        num_eq_xys: usize,
        num_polys: usize,
    ) -> Self {
        let mut offset = Self::default();
        offset.0 = num_constants;
        offset.1 = offset.0 + 1;
        offset.2 = offset.1 + num_lagranges;
        offset.3 = offset.2 + num_eq_xys;
        offset.4 = offset.3 + num_polys;
        offset
    }

    pub(crate) fn identity(&self) -> usize {
        self.0
    }

    pub(crate) fn lagranges(&self) -> usize {
        self.1
    }

    pub(crate) fn eq_xys(&self) -> usize {
        self.2
    }

    pub(crate) fn polys(&self) -> usize {
        self.3
    }

    pub(crate) fn calculations(&self) -> usize {
        self.4
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ValueSource {
    Constant(usize),
    Identity,
    Lagrange(usize),
    EqXY(usize),
    Poly(usize),
    Calculation(usize),
}

impl ValueSource {
    fn indexed(&self, offsets: &Offsets) -> usize {
        use ValueSource::*;
        match self {
            Constant(idx) => *idx,
            Identity => offsets.identity(),
            Lagrange(idx) => offsets.lagranges() + idx,
            EqXY(idx) => offsets.eq_xys() + idx,
            Poly(idx) => offsets.polys() + idx,
            Calculation(idx) => offsets.calculations() + idx,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Calculation<T> {
    Negated(T),
    Add(T, T),
    Sub(T, T),
    Mul(T, T),
}

impl Calculation<ValueSource> {
    fn indexed(&self, offsets: &Offsets) -> Calculation<usize> {
        use Calculation::*;
        match self {
            Negated(value) => Negated(value.indexed(offsets)),
            Add(lhs, rhs) => Add(lhs.indexed(offsets), rhs.indexed(offsets)),
            Sub(lhs, rhs) => Sub(lhs.indexed(offsets), rhs.indexed(offsets)),
            Mul(lhs, rhs) => Mul(lhs.indexed(offsets), rhs.indexed(offsets)),
        }
    }
}

impl Calculation<usize> {
    pub(crate) fn calculate<F: Field>(&self, cache: &mut [F], idx: usize) {
        use Calculation::*;
        cache[idx] = match self {
            Negated(value) => -cache[*value],
            Add(lhs, rhs) => cache[*lhs] + &cache[*rhs],
            Sub(lhs, rhs) => cache[*lhs] - &cache[*rhs],
            Mul(lhs, rhs) => cache[*lhs] * &cache[*rhs],
        };
    }
}
