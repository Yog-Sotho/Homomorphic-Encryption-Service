use crate::params::MAX_INPUTS;
use crate::types::{IntegerType, PlainValue, ValueType};
use serde::{Deserialize, Serialize};

/// Homomorphic operations. Arithmetic wraps modulo 2^bits of the input type;
/// comparisons return an encrypted boolean.
///
/// Every operation except [`Sum`](Operation::Sum) takes two operands: two
/// ciphertexts, or one ciphertext and a plaintext `scalar` as the right-hand side.
/// `Sum` adds 2 to [`MAX_INPUTS`] ciphertexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type), sqlx(rename_all = "lowercase"))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum Operation {
    Add,
    Subtract,
    Multiply,
    Min,
    Max,
    /// `a == b`
    Eq,
    /// `a != b`
    Ne,
    /// `a < b`
    Lt,
    /// `a <= b`
    Le,
    /// `a > b`
    Gt,
    /// `a >= b`
    Ge,
    /// The wrapping sum of all inputs.
    Sum,
}

impl Operation {
    pub const ALL: [Operation; 12] = [
        Operation::Add,
        Operation::Subtract,
        Operation::Multiply,
        Operation::Min,
        Operation::Max,
        Operation::Eq,
        Operation::Ne,
        Operation::Lt,
        Operation::Le,
        Operation::Gt,
        Operation::Ge,
        Operation::Sum,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Operation::Add => "add",
            Operation::Subtract => "subtract",
            Operation::Multiply => "multiply",
            Operation::Min => "min",
            Operation::Max => "max",
            Operation::Eq => "eq",
            Operation::Ne => "ne",
            Operation::Lt => "lt",
            Operation::Le => "le",
            Operation::Gt => "gt",
            Operation::Ge => "ge",
            Operation::Sum => "sum",
        }
    }

    /// The inverse of [`as_str`](Self::as_str).
    pub fn parse(name: &str) -> Option<Operation> {
        Self::ALL.into_iter().find(|op| op.as_str() == name)
    }

    pub fn is_comparison(self) -> bool {
        matches!(
            self,
            Operation::Eq
                | Operation::Ne
                | Operation::Lt
                | Operation::Le
                | Operation::Gt
                | Operation::Ge
        )
    }

    /// The type of the encrypted result for inputs of type `input`.
    pub fn result_type(self, input: IntegerType) -> ValueType {
        if self.is_comparison() {
            ValueType::Bool
        } else {
            input.into()
        }
    }

    /// Checks the operand shape: `ciphertexts` encrypted inputs, plus a plaintext
    /// right-hand side if `scalar`. The error is safe to show to the caller.
    pub fn check_operands(self, ciphertexts: usize, scalar: bool) -> Result<(), String> {
        match (self, ciphertexts, scalar) {
            (Operation::Sum, _, true) => Err("sum does not take a scalar".into()),
            (Operation::Sum, 2..=MAX_INPUTS, false) => Ok(()),
            (Operation::Sum, n, false) => Err(format!(
                "sum takes 2 to {MAX_INPUTS} encrypted inputs, got {n}"
            )),
            (_, 2, false) | (_, 1, true) => Ok(()),
            (op, n, false) => Err(format!("{op} takes exactly 2 encrypted inputs, got {n}")),
            (op, n, true) => Err(format!(
                "{op} with a scalar takes exactly 1 encrypted input, got {n}"
            )),
        }
    }

    /// The plaintext result the decrypted homomorphic result must equal.
    /// `operands` are in `ty`'s range (the scalar, if any, last); their number
    /// must satisfy [`check_operands`](Self::check_operands).
    pub fn apply_plain(self, ty: IntegerType, operands: &[i128]) -> PlainValue {
        if self == Operation::Sum {
            let sum = operands.iter().fold(0i128, |acc, &v| acc.wrapping_add(v));
            return PlainValue::Int(ty.wrap(sum));
        }
        assert_eq!(operands.len(), 2, "{self} takes two operands");
        let (a, b) = (operands[0], operands[1]);
        // i128 wraps modulo 2^128, a multiple of 2^bits, so wrapping there and
        // then reducing gives the result modulo 2^bits.
        match self {
            Operation::Add => PlainValue::Int(ty.wrap(a.wrapping_add(b))),
            Operation::Subtract => PlainValue::Int(ty.wrap(a.wrapping_sub(b))),
            Operation::Multiply => PlainValue::Int(ty.wrap(a.wrapping_mul(b))),
            Operation::Min => PlainValue::Int(a.min(b)),
            Operation::Max => PlainValue::Int(a.max(b)),
            Operation::Eq => PlainValue::Bool(a == b),
            Operation::Ne => PlainValue::Bool(a != b),
            Operation::Lt => PlainValue::Bool(a < b),
            Operation::Le => PlainValue::Bool(a <= b),
            Operation::Gt => PlainValue::Bool(a > b),
            Operation::Ge => PlainValue::Bool(a >= b),
            Operation::Sum => unreachable!(),
        }
    }
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Operation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Operation::parse(s).ok_or_else(|| {
            let names: Vec<_> = Operation::ALL.iter().map(|op| op.as_str()).collect();
            format!(
                "unknown operation {s:?} (expected one of {})",
                names.join(", ")
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use IntegerType::*;

    fn int(op: Operation, ty: IntegerType, operands: &[i128]) -> i128 {
        match op.apply_plain(ty, operands) {
            PlainValue::Int(v) => v,
            other => panic!("{op} returned {other:?}"),
        }
    }

    #[test]
    fn names_round_trip_and_match_serde() {
        for op in Operation::ALL {
            assert_eq!(Operation::parse(op.as_str()), Some(op));
            assert_eq!(op.to_string().parse::<Operation>(), Ok(op));
            assert_eq!(serde_json::to_value(op).unwrap(), op.as_str());
        }
        assert!("divide".parse::<Operation>().is_err());
    }

    #[test]
    fn arithmetic_wraps_modulo_2_bits() {
        assert_eq!(int(Operation::Multiply, U16, &[300, 300]), 24464);
        assert_eq!(int(Operation::Subtract, U16, &[3, 10]), 65529);
        assert_eq!(int(Operation::Add, U16, &[40_000, 30_000]), 4464);
        assert_eq!(int(Operation::Add, I8, &[100, 100]), -56);
        assert_eq!(int(Operation::Multiply, I16, &[-300, 300]), -24464);
        let max = u64::MAX as i128;
        assert_eq!(int(Operation::Multiply, U64, &[max, max]), 1);
        assert_eq!(int(Operation::Add, U64, &[max, 1]), 0);
        assert_eq!(
            int(Operation::Multiply, I64, &[i64::MIN as i128, -1]),
            i64::MIN as i128
        );
        assert_eq!(int(Operation::Sum, U8, &[200, 100, 1]), 45);
        assert_eq!(int(Operation::Sum, I32, &[-5, 2, -3]), -6);
    }

    #[test]
    fn min_max_and_comparisons_respect_signedness() {
        assert_eq!(int(Operation::Min, U16, &[9, 4]), 4);
        assert_eq!(int(Operation::Max, I8, &[-9, 4]), 4);
        assert_eq!(int(Operation::Min, I8, &[-9, 4]), -9);
        let cmp = |op, a, b| op_bool(op, I16, a, b);
        assert!(cmp(Operation::Lt, -1, 0));
        assert!(cmp(Operation::Ge, 3, 3));
        assert!(!cmp(Operation::Gt, 3, 3));
        assert!(cmp(Operation::Ne, 1, 2));
        assert!(cmp(Operation::Le, -5, -5));
        assert!(cmp(Operation::Eq, 7, 7));
        assert_eq!(Operation::Lt.result_type(U32), ValueType::Bool);
        assert_eq!(Operation::Add.result_type(I8), ValueType::I8);
    }

    fn op_bool(op: Operation, ty: IntegerType, a: i128, b: i128) -> bool {
        match op.apply_plain(ty, &[a, b]) {
            PlainValue::Bool(v) => v,
            other => panic!("{op} returned {other:?}"),
        }
    }

    #[test]
    fn operand_shapes() {
        assert!(Operation::Add.check_operands(2, false).is_ok());
        assert!(Operation::Lt.check_operands(1, true).is_ok());
        assert!(Operation::Add.check_operands(1, false).is_err());
        assert!(Operation::Add.check_operands(2, true).is_err());
        assert!(Operation::Add.check_operands(3, false).is_err());
        assert!(Operation::Sum.check_operands(2, false).is_ok());
        assert!(Operation::Sum.check_operands(MAX_INPUTS, false).is_ok());
        assert!(Operation::Sum
            .check_operands(MAX_INPUTS + 1, false)
            .is_err());
        assert!(Operation::Sum.check_operands(1, false).is_err());
        assert!(Operation::Sum.check_operands(2, true).is_err());
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        /// The result native Rust integers give, the reference for the oracle.
        fn native(op: Operation, ty: IntegerType, operands: &[i128]) -> PlainValue {
            macro_rules! with {
                ($t:ty) => {{
                    let v: Vec<$t> = operands.iter().map(|&x| x as $t).collect();
                    let (a, b) = (v[0], *v.get(1).unwrap_or(&0));
                    match op {
                        Operation::Add => PlainValue::Int(a.wrapping_add(b) as i128),
                        Operation::Subtract => PlainValue::Int(a.wrapping_sub(b) as i128),
                        Operation::Multiply => PlainValue::Int(a.wrapping_mul(b) as i128),
                        Operation::Min => PlainValue::Int(a.min(b) as i128),
                        Operation::Max => PlainValue::Int(a.max(b) as i128),
                        Operation::Eq => PlainValue::Bool(a == b),
                        Operation::Ne => PlainValue::Bool(a != b),
                        Operation::Lt => PlainValue::Bool(a < b),
                        Operation::Le => PlainValue::Bool(a <= b),
                        Operation::Gt => PlainValue::Bool(a > b),
                        Operation::Ge => PlainValue::Bool(a >= b),
                        Operation::Sum => PlainValue::Int(
                            v.iter().fold(0 as $t, |acc, &x| acc.wrapping_add(x)) as i128,
                        ),
                    }
                }};
            }
            match ty {
                U8 => with!(u8),
                U16 => with!(u16),
                U32 => with!(u32),
                U64 => with!(u64),
                I8 => with!(i8),
                I16 => with!(i16),
                I32 => with!(i32),
                I64 => with!(i64),
            }
        }

        fn typed_operands() -> impl Strategy<Value = (Operation, IntegerType, Vec<i128>)> {
            (
                proptest::sample::select(Operation::ALL.to_vec()),
                proptest::sample::select(IntegerType::ALL.to_vec()),
            )
                .prop_flat_map(|(op, ty)| {
                    let count = if op == Operation::Sum {
                        2..=MAX_INPUTS
                    } else {
                        2..=2
                    };
                    let values = proptest::collection::vec(ty.min_value()..=ty.max_value(), count);
                    (Just(op), Just(ty), values)
                })
        }

        proptest! {
            #[test]
            fn the_oracle_matches_native_integers((op, ty, operands) in typed_operands()) {
                prop_assert_eq!(op.apply_plain(ty, &operands), native(op, ty, &operands));
            }

            #[test]
            fn wrapping_lands_in_range_and_is_congruent(
                ty in proptest::sample::select(IntegerType::ALL.to_vec()),
                value in -(1i128 << 100)..(1i128 << 100),
            ) {
                let wrapped = ty.wrap(value);
                prop_assert!(ty.min_value() <= wrapped && wrapped <= ty.max_value());
                prop_assert_eq!((value - wrapped).rem_euclid(1i128 << ty.bits()), 0);
                prop_assert_eq!(ty.wrap(wrapped), wrapped);
            }

            #[test]
            fn values_parse_back_and_out_of_range_ones_do_not(
                ty in proptest::sample::select(IntegerType::ALL.to_vec()),
                value in any::<i128>(),
            ) {
                let parsed = ty.parse_value(&value.to_string());
                if (ty.min_value()..=ty.max_value()).contains(&value) {
                    prop_assert_eq!(parsed, Ok(value));
                } else {
                    prop_assert!(parsed.is_err());
                }
            }
        }
    }
}
