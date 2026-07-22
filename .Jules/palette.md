## 2026-05-17 - Missing Input Labels in Core Authentication and Dashboard Forms
**Learning:** Discovered a consistent pattern of missing `<label>` elements for form inputs in the Svelte routes (`login`, `dashboard`). This degrades accessibility for screen reader users and makes the UI less intuitive for keyboard navigation.
**Action:** Always ensure every form `<input>` has an associated `<label>` using the `id` and `for` attributes. For secondary actions like switching between login and registration, use buttons with clear descriptive text or ARIA roles rather than just separate buttons.

## 2026-05-22 - Build Failures and UX Constraints
**Learning:** Production builds in this SvelteKit environment are sensitive to Vite configuration and dependency versions. Specifically, 'manualChunks' for 'axios' and incompatible versions of '@sveltejs/vite-plugin-svelte' cause immediate build failures.
**Action:** Prioritize build stability over non-essential optimizations (like manual chunking) and ensure all UX improvements are verified with 'pnpm build' in a clean environment.

## 2026-05-25 - Enhancing Async Feedback and Control
**Learning:** Initial feedback after job submission was slightly delayed until the first poll returned. Using `<output aria-live="polite">` for status messages and providing a way to "Clear" the dashboard state significantly improves the user's sense of control and accessibility.
**Action:** Always provide immediate 'pending' feedback for async tasks and include 'Clear' or 'Reset' actions for ephemeral dashboard results. Use semantic `<output>` for dynamic status text.

## 2026-06-08 - Standardizing Card Headers with Utility Actions
**Learning:** Found that the '.card-header' class provides a consistent flex layout for titles and secondary actions (like 'Clear' or 'Randomize'). Using this pattern for the 'New Computation' card makes the utility action easily discoverable without cluttering the main form area.
**Action:** Use '.card-header' to group card titles with relevant utility buttons, maintaining a clear visual hierarchy and consistent layout across different dashboard modules.

## 2026-06-15 - Context-Aware Autocomplete for Shared Auth Forms
**Learning:** In applications where Login and Registration share a form or component, using a static `autocomplete="current-password"` can confuse password managers during registration. Dynamically toggling between `current-password` and `new-password` ensures browser tools provide the correct suggestions.
**Action:** Always bind the `autocomplete` attribute of password fields to the component's mode (e.g., `isLogin ? 'current-password' : 'new-password'`) to maintain high usability and accessibility for password management.

## 2026-06-15 - Robust Password Visibility Toggle Pattern
**Learning:** When implementing a password visibility toggle, using a '.password-wrapper' with relative positioning and an absolute-positioned toggle button ensures a stable layout. Furthermore, explicitly setting 'exact=True' in Playwright's 'get_by_label' prevents selector collisions with the toggle button's 'aria-label' if it contains the word "password".
**Action:** Always wrap password inputs for utility actions, apply 'padding-right' to the input to prevent text overlap, and use precise Playwright locators to avoid ambiguity during testing.

## 2026-07-20 - Real-Time Programmatic Input Clamping and Tab Accessibility
**Learning:** For custom tab controls, toggling the `aria-pressed` attribute dynamically provides screen readers with the correct state. Additionally, rather than relying on brittle HTML5 forms or displaying static validation warning text that doesn't actually limit the raw input, programmatically clamping input values in real-time using Svelte reactive statements (`$: if (val > max) val = max`) creates an exceptionally smooth, responsive user experience that completely prevents validation blocking and layout breaking.
**Action:** Always prefer real-time programmatic clamping/sanitization of user input over static tooltip notifications, and ensure custom interactive tabs have dynamic `aria-pressed` attributes.

## 2026-07-22 - Aligning Interactive Password Criteria Lists
**Learning:** Providing a real-time list of password complexity requirements on the frontend that perfectly mirrors the backend security guidelines significantly improves interactive confidence. Highlighting met/unmet requirements prevents frustrating form rejects.
**Action:** Always verify local form rules against the centralized backend validation patterns (e.g. `validation.rs`), and supply dynamic UI checklist states to assist users in selecting correct credentials.
