//! [`RawJson`] — the pre-serialized reply body shared by every trace handler.

use std::sync::{Arc, LazyLock};

use serde_json::value::RawValue;

/// A pre-serialized JSON response body: the reply type of every trace handler and the
/// value the response cache stores. Its `Serialize` impl splices the bytes verbatim (the
/// [`RawValue`] mechanism), so serving one — fresh or cached — never rebuilds or
/// re-serializes the JSON tree: [`RawJson::try_new`] is the single fill-path
/// serialization, and cloning shares the bytes without copying them.
///
/// The `Box` inside the `Arc` is deliberate: it adopts the serializer's allocation as-is.
/// `Arc<RawValue>` (an unsized pointee) cannot, so building one would memcpy the whole
/// body next to a fresh refcount — a second full-body copy on every fill.
#[derive(Debug, Clone)]
pub struct RawJson(Arc<Box<RawValue>>);

impl RawJson {
    /// Serializes a value into its `RawJson` reply body — the one serialization a
    /// response undergoes.
    pub fn try_new<T: serde::Serialize + ?Sized>(value: &T) -> serde_json::Result<Self> {
        serde_json::value::to_raw_value(value).map(|raw| Self(Arc::new(raw)))
    }

    /// The serialized length in bytes.
    pub fn byte_len(&self) -> usize {
        self.0.get().len()
    }

    /// The JSON literal `null`.
    pub fn null() -> Self {
        static NULL: LazyLock<RawJson> =
            LazyLock::new(|| RawJson(Arc::new(RawValue::NULL.to_owned())));
        NULL.clone()
    }

    /// The raw serialized JSON.
    #[cfg(test)]
    pub fn as_str(&self) -> &str {
        self.0.get()
    }

    /// Whether two handles share the same underlying bytes (a hit is an `Arc` clone).
    #[cfg(test)]
    pub fn shares_bytes_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl serde::Serialize for RawJson {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Delegate to the pointee explicitly — `Arc<T>` itself is only `Serialize`
        // behind serde's optional `rc` feature.
        self.0.as_ref().serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// The property the whole design rests on: serializing a [`RawJson`] (what jsonrpsee
    /// does to build the reply) emits the stored bytes verbatim — no re-parse, no
    /// normalization, byte-for-byte what the fill request serialized.
    #[test]
    fn raw_json_serializes_verbatim() {
        let value = json!({"key": "value", "nested": [1, 2, {"deep": null}]});
        let raw = RawJson::try_new(&value).expect("serialize");
        assert_eq!(raw.byte_len(), raw.as_str().len());
        assert_eq!(serde_json::to_string(&raw).expect("splice"), raw.as_str());
        assert_eq!(serde_json::to_string(&raw).expect("splice"), value.to_string());
        assert_eq!(serde_json::to_string(&RawJson::null()).expect("splice"), "null");
    }
}
