//! Cache key implementation.

use stria_proto::{class::Class, Name, Question, rtype::Type};
use std::hash::{Hash, Hasher};

/// Cache key for DNS records.
#[derive(Debug, Clone, Eq)]
pub struct CacheKey {
    /// Domain name (lowercased for lookup).
    name: Name,

    /// Record type.
    rtype: Type,

    /// Record class.
    rclass: Class,
}

impl CacheKey {
    /// Creates a new cache key.
    pub fn new(name: Name, rtype: Type, rclass: Class) -> Self {
        Self {
            name: name.lowercased(),
            rtype,
            rclass,
        }
    }

    /// Creates a cache key from a question.
    pub fn from_question(question: &Question) -> Self {
        Self::new(question.qname.clone(), question.qtype, question.qclass)
    }

    /// Returns the domain name.
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Returns the record type.
    pub fn rtype(&self) -> Type {
        self.rtype
    }

    /// Returns the record class.
    pub fn rclass(&self) -> Class {
        self.rclass
    }
}

impl PartialEq for CacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.rtype == other.rtype && self.rclass == other.rclass
    }
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.rtype.to_u16().hash(state);
        self.rclass.to_u16().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stria_proto::{RecordClass, RecordType};
    use std::str::FromStr;

    #[test]
    fn test_cache_key_equality() {
        let key1 = CacheKey::new(
            Name::from_str("example.com").unwrap(),
            Type::Known(RecordType::A),
            Class::Known(RecordClass::IN),
        );

        let key2 = CacheKey::new(
            Name::from_str("EXAMPLE.COM").unwrap(),
            Type::Known(RecordType::A),
            Class::Known(RecordClass::IN),
        );

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_key_hash() {
        use std::collections::hash_map::DefaultHasher;

        let key1 = CacheKey::new(
            Name::from_str("example.com").unwrap(),
            Type::Known(RecordType::A),
            Class::Known(RecordClass::IN),
        );

        let key2 = CacheKey::new(
            Name::from_str("EXAMPLE.COM").unwrap(),
            Type::Known(RecordType::A),
            Class::Known(RecordClass::IN),
        );

        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        key1.hash(&mut h1);
        key2.hash(&mut h2);

        assert_eq!(h1.finish(), h2.finish());
    }
}
