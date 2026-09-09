use std::collections::HashMap;

/// Content filter for subscription message filtering.
///
/// A content filter holds a name, SQL-like expression, and parameter map.
/// The expression is stored as-is; actual evaluation happens in C++ RMW layer.
#[derive(Clone)]
pub struct ContentFilter {
    /// Human-readable filter name.
    pub name: String,
    /// SQL-like filter expression (e.g. "x > 5").
    pub expression: String,
    /// Named parameters for the expression.
    pub parameters: HashMap<String, String>,
}

impl ContentFilter {
    /// Create a new content filter.
    ///
    /// # Arguments
    /// * `name` - Filter name
    /// * `expression` - SQL-like expression string
    /// * `parameters` - Named parameter map
    ///
    /// # Returns
    /// New ContentFilter instance.
    pub fn new(name: &str, expression: &str, parameters: HashMap<String, String>) -> Self {
        Self {
            name: name.to_string(),
            expression: expression.to_string(),
            parameters,
        }
    }

    /// Check if the filter has no expression (disabled).
    ///
    /// # Returns
    /// `true` if the expression string is empty.
    pub fn is_empty(&self) -> bool {
        self.expression.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_filter_create() {
        let filter = ContentFilter::new("test", "x > 5", HashMap::new());
        assert!(!filter.is_empty());
        assert_eq!(filter.name, "test");
        assert_eq!(filter.expression, "x > 5");
    }

    #[test]
    fn test_content_filter_with_params() {
        let mut params = HashMap::new();
        params.insert("threshold".to_string(), "10".to_string());
        let filter = ContentFilter::new("param_test", "x > :threshold", params);
        assert_eq!(filter.parameters.get("threshold"), Some(&"10".to_string()));
    }

    #[test]
    fn test_content_filter_empty() {
        let filter = ContentFilter::new("empty", "", HashMap::new());
        assert!(filter.is_empty());
    }
}
