pub fn is_valid_email(email: &str) -> bool {
    if email.len() > 254 {
        return false;
    }
    if let Some(at_pos) = email.find('@') {
        let local = &email[..at_pos];
        let domain = &email[at_pos + 1..];
        if local.is_empty() || domain.is_empty() {
            return false;
        }
        if let Some(dot_pos) = domain.rfind('.') {
            // Ensure there is at least one character before and after the last dot in the domain
            dot_pos > 0 && dot_pos < domain.len() - 1
        } else {
            false
        }
    } else {
        false
    }
}

pub fn is_strong_password(password: &str) -> bool {
    password.len() >= 10
        && password.len() <= 128
        && password.chars().any(|c| c.is_uppercase())
        && password.chars().any(|c| c.is_lowercase())
        && password.chars().any(|c| c.is_ascii_digit())
        && password.chars().any(|c| !c.is_alphanumeric())
}

pub const PASSWORD_REQUIREMENTS: &str = "Password must be between 10 and 128 characters and include uppercase, lowercase, a digit, and a special character.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_email() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("user.name@sub.example.com"));
        assert!(!is_valid_email("user@example"));
        assert!(!is_valid_email("user@.com"));
        assert!(!is_valid_email("user@example."));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email("userexample.com"));
        // Max length test (254 characters)
        let long_local = "a".repeat(242);
        let valid_long_email = format!("{}@example.com", long_local);
        assert_eq!(valid_long_email.len(), 254);
        assert!(is_valid_email(&valid_long_email));
        let too_long_email = format!("{}a@example.com", long_local);
        assert_eq!(too_long_email.len(), 255);
        assert!(!is_valid_email(&too_long_email));
    }

    #[test]
    fn test_is_strong_password() {
        assert!(is_strong_password("Password123!"));
        assert!(!is_strong_password("Pass123!")); // too short
        assert!(!is_strong_password("password123!")); // no uppercase
        assert!(!is_strong_password("PASSWORD123!")); // no lowercase
        assert!(!is_strong_password("Password!!!")); // no digit
        assert!(!is_strong_password("Password123")); // no special char

        // Max length test (128 characters)
        let mut max_len_pass = "Password123!".to_string();
        max_len_pass.push_str(&"a".repeat(116));
        assert_eq!(max_len_pass.len(), 128);
        assert!(is_strong_password(&max_len_pass));

        let mut too_long_pass = "Password123!".to_string();
        too_long_pass.push_str(&"a".repeat(117));
        assert_eq!(too_long_pass.len(), 129);
        assert!(!is_strong_password(&too_long_pass));
    }
}
