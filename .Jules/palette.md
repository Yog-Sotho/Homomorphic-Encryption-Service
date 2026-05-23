## 2026-05-17 - Missing Input Labels in Core Authentication and Dashboard Forms
**Learning:** Discovered a consistent pattern of missing `<label>` elements for form inputs in the Svelte routes (`login`, `dashboard`). This degrades accessibility for screen reader users and makes the UI less intuitive for keyboard navigation.
**Action:** Always ensure every form `<input>` has an associated `<label>` using the `id` and `for` attributes. For secondary actions like switching between login and registration, use buttons with clear descriptive text or ARIA roles rather than just separate buttons.

## 2026-05-18 - Enhancing Dynamic Content and Data Utility
**Learning:** Found that non-human-readable data (like Base64 strings) can be cumbersome for users to manage manually. Providing a "Copy to Clipboard" utility significantly improves the experience. Additionally, using `aria-live` on status containers ensures that asynchronous updates (like job status changes) are properly announced to screen reader users.
**Action:** For non-readable strings or results, always provide a "Copy to Clipboard" button with visual feedback. Use `aria-live="polite"` on containers that receive dynamic content updates.
