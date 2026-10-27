use serde::{Deserialize, Serialize};

/// Binary operations on `FheUint16`. Arithmetic wraps modulo 2^16.
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
}

impl Operation {
    pub const ALL: [Operation; 5] = [
        Operation::Add,
        Operation::Subtract,
        Operation::Multiply,
        Operation::Min,
        Operation::Max,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Operation::Add => "add",
            Operation::Subtract => "subtract",
            Operation::Multiply => "multiply",
            Operation::Min => "min",
            Operation::Max => "max",
        }
    }

    /// The inverse of [`as_str`](Self::as_str).
    pub fn parse(name: &str) -> Option<Operation> {
        Self::ALL.into_iter().find(|op| op.as_str() == name)
    }

    /// The plaintext result the decrypted homomorphic result must equal.
    pub fn apply_plain(self, a: u16, b: u16) -> u16 {
        match self {
            Operation::Add => a.wrapping_add(b),
            Operation::Subtract => a.wrapping_sub(b),
            Operation::Multiply => a.wrapping_mul(b),
            Operation::Min => a.min(b),
            Operation::Max => a.max(b),
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
    fn plaintext_semantics_wrap_modulo_2_16() {
        assert_eq!(Operation::Multiply.apply_plain(300, 300), 24464);
        assert_eq!(Operation::Subtract.apply_plain(3, 10), 65529);
        assert_eq!(Operation::Add.apply_plain(40_000, 30_000), 4464);
        assert_eq!(Operation::Min.apply_plain(9, 4), 4);
        assert_eq!(Operation::Max.apply_plain(9, 4), 9);
    }
}
