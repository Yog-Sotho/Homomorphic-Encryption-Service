use serde::{Deserialize, Serialize};
use std::fmt;

/// The encrypted integer types jobs can compute on. Arithmetic wraps modulo
/// 2^bits; signed types use two's complement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type), sqlx(rename_all = "lowercase"))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum IntegerType {
    U8,
    #[default]
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
}

impl IntegerType {
    pub const ALL: [IntegerType; 8] = [
        IntegerType::U8,
        IntegerType::U16,
        IntegerType::U32,
        IntegerType::U64,
        IntegerType::I8,
        IntegerType::I16,
        IntegerType::I32,
        IntegerType::I64,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            IntegerType::U8 => "u8",
            IntegerType::U16 => "u16",
            IntegerType::U32 => "u32",
            IntegerType::U64 => "u64",
            IntegerType::I8 => "i8",
            IntegerType::I16 => "i16",
            IntegerType::I32 => "i32",
            IntegerType::I64 => "i64",
        }
    }

    pub fn parse(name: &str) -> Option<IntegerType> {
        Self::ALL.into_iter().find(|t| t.as_str() == name)
    }

    /// The TFHE-rs type ciphertexts of this type are (`FheUint16`, `FheInt8`, …).
    pub fn tfhe_name(self) -> &'static str {
        match self {
            IntegerType::U8 => "FheUint8",
            IntegerType::U16 => "FheUint16",
            IntegerType::U32 => "FheUint32",
            IntegerType::U64 => "FheUint64",
            IntegerType::I8 => "FheInt8",
            IntegerType::I16 => "FheInt16",
            IntegerType::I32 => "FheInt32",
            IntegerType::I64 => "FheInt64",
        }
    }

    pub fn bits(self) -> u32 {
        match self {
            IntegerType::U8 | IntegerType::I8 => 8,
            IntegerType::U16 | IntegerType::I16 => 16,
            IntegerType::U32 | IntegerType::I32 => 32,
            IntegerType::U64 | IntegerType::I64 => 64,
        }
    }

    pub fn is_signed(self) -> bool {
        matches!(
            self,
            IntegerType::I8 | IntegerType::I16 | IntegerType::I32 | IntegerType::I64
        )
    }

    pub fn min_value(self) -> i128 {
        if self.is_signed() {
            -(1i128 << (self.bits() - 1))
        } else {
            0
        }
    }

    pub fn max_value(self) -> i128 {
        if self.is_signed() {
            (1i128 << (self.bits() - 1)) - 1
        } else {
            (1i128 << self.bits()) - 1
        }
    }

    /// Reduces `value` modulo 2^bits into this type's range, as the encrypted
    /// arithmetic does.
    pub fn wrap(self, value: i128) -> i128 {
        let modulus = 1i128 << self.bits();
        let reduced = value.rem_euclid(modulus);
        if self.is_signed() && reduced > self.max_value() {
            reduced - modulus
        } else {
            reduced
        }
    }

    /// Parses a decimal value, refusing anything outside this type's range.
    pub fn parse_value(self, text: &str) -> Result<i128, String> {
        let value: i128 = text
            .trim()
            .parse()
            .map_err(|_| format!("{text:?} is not a whole number"))?;
        if value < self.min_value() || value > self.max_value() {
            return Err(format!(
                "{value} is outside the {} range ({} to {})",
                self.as_str(),
                self.min_value(),
                self.max_value()
            ));
        }
        Ok(value)
    }
}

impl fmt::Display for IntegerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for IntegerType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IntegerType::parse(s).ok_or_else(|| {
            let names: Vec<_> = IntegerType::ALL.iter().map(|t| t.as_str()).collect();
            format!("unknown type {s:?} (expected one of {})", names.join(", "))
        })
    }
}

/// The type of a job's encrypted result: the input type, or `bool` for comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type), sqlx(rename_all = "lowercase"))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum ValueType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
}

impl From<IntegerType> for ValueType {
    fn from(t: IntegerType) -> Self {
        match t {
            IntegerType::U8 => ValueType::U8,
            IntegerType::U16 => ValueType::U16,
            IntegerType::U32 => ValueType::U32,
            IntegerType::U64 => ValueType::U64,
            IntegerType::I8 => ValueType::I8,
            IntegerType::I16 => ValueType::I16,
            IntegerType::I32 => ValueType::I32,
            IntegerType::I64 => ValueType::I64,
        }
    }
}

impl ValueType {
    /// The integer type, or `None` for `bool`.
    pub fn integer(self) -> Option<IntegerType> {
        IntegerType::ALL
            .into_iter()
            .find(|&t| ValueType::from(t) == self)
    }

    pub fn as_str(self) -> &'static str {
        self.integer().map_or("bool", IntegerType::as_str)
    }
}

impl std::str::FromStr for ValueType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "bool" {
            return Ok(ValueType::Bool);
        }
        s.parse::<IntegerType>()
            .map(ValueType::from)
            .map_err(|e| format!("{e} or bool"))
    }
}

impl fmt::Display for ValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A decrypted (or expected) value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlainValue {
    Bool(bool),
    Int(i128),
}

impl fmt::Display for PlainValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlainValue::Bool(b) => write!(f, "{b}"),
            PlainValue::Int(v) => write!(f, "{v}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_and_wrapping_follow_twos_complement() {
        assert_eq!(
            (IntegerType::U8.min_value(), IntegerType::U8.max_value()),
            (0, 255)
        );
        assert_eq!(
            (IntegerType::I8.min_value(), IntegerType::I8.max_value()),
            (-128, 127)
        );
        assert_eq!(IntegerType::U64.max_value(), u64::MAX as i128);
        assert_eq!(IntegerType::I64.min_value(), i64::MIN as i128);
        assert_eq!(IntegerType::U16.wrap(70_000), 4464);
        assert_eq!(IntegerType::U16.wrap(-7), 65529);
        assert_eq!(IntegerType::I8.wrap(128), -128);
        assert_eq!(IntegerType::I8.wrap(-129), 127);
        assert_eq!(
            IntegerType::I64.wrap(i64::MAX as i128 + 1),
            i64::MIN as i128
        );
    }

    #[test]
    fn values_are_parsed_within_range() {
        assert_eq!(IntegerType::I16.parse_value(" -300 "), Ok(-300));
        assert_eq!(
            IntegerType::U64.parse_value("18446744073709551615"),
            Ok(u64::MAX as i128)
        );
        assert!(IntegerType::U8.parse_value("256").is_err());
        assert!(IntegerType::U8.parse_value("-1").is_err());
        assert!(IntegerType::I8.parse_value("1.5").is_err());
    }

    #[test]
    fn names_round_trip() {
        for t in IntegerType::ALL {
            assert_eq!(t.as_str().parse::<IntegerType>(), Ok(t));
            assert_eq!(serde_json::to_value(t).unwrap(), t.as_str());
            assert_eq!(ValueType::from(t).integer(), Some(t));
            assert_eq!(ValueType::from(t).as_str(), t.as_str());
        }
        assert_eq!(ValueType::Bool.integer(), None);
        assert_eq!("bool".parse::<ValueType>(), Ok(ValueType::Bool));
        assert_eq!("i64".parse::<ValueType>(), Ok(ValueType::I64));
        assert_eq!(serde_json::to_value(ValueType::Bool).unwrap(), "bool");
        assert!("u128".parse::<IntegerType>().is_err());
    }
}
