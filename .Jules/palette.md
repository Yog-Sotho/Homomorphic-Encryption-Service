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

## 2026-06-12 - Password Visibility Toggle with Text Labels
**Learning:** In environments without a dedicated icon library, a text-based "SHOW/HIDE" toggle is a clear and accessible alternative for password visibility. Using absolute positioning within a relative container (`.password-wrapper`) keeps the button integrated with the input field.
**Action:** Implement password visibility toggles using a `.password-wrapper` container with an absolute-positioned toggle button (`type="button"`) and reactive state. Ensure the input has `padding-right` to prevent text overlap with the toggle.
