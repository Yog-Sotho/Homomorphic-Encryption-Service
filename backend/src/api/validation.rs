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
    }

    #[test]
    fn test_is_strong_password() {
        assert!(is_strong_password("Password123!"));
        assert!(!is_strong_password("Pass123!")); // too short
        assert!(!is_strong_password("password123!")); // no uppercase
        assert!(!is_strong_password("PASSWORD123!")); // no lowercase
        assert!(!is_strong_password("Password!!!")); // no digit
        assert!(!is_strong_password("Password123")); // no special char
    }

    #[test]
    fn test_is_valid_email_over_length_limit() {
        // Create an email with 250 local characters + "@example.com" = 262 characters
        let long_email = format!("{}@example.com", "a".repeat(250));
        assert_eq!(long_email.len(), 262);
        assert!(!is_valid_email(&long_email));
    }

    #[test]
    fn test_is_strong_password_over_length_limit() {
        // Create a strong password (diversity-wise) with 132 characters (over 128 limit)
        let long_password = "P1!a".repeat(33);
        assert_eq!(long_password.len(), 132);
        assert!(!is_strong_password(&long_password));
    }
}
