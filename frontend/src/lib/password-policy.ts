/** Mirrors the backend's `is_strong_password` (backend/src/api/validation.rs). */
export const PASSWORD_REQUIREMENTS =
  '10–128 characters with an uppercase letter, a lowercase letter, a digit and a symbol.';

export function isStrongPassword(p: string): boolean {
  // The backend measures length in UTF-8 bytes.
  const bytes = new TextEncoder().encode(p).length;
  return (
    bytes >= 10 &&
    bytes <= 128 &&
    /\p{Lu}/u.test(p) &&
    /\p{Ll}/u.test(p) &&
    /[0-9]/.test(p) &&
    /[^\p{L}\p{N}]/u.test(p)
  );
}
