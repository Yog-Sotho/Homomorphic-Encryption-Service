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

## 2026-06-15 - Password Visibility Toggle UX
**Learning:** Implementing a password visibility toggle with a text-based button (e.g., "SHOW"/"HIDE") requires careful management of input padding to prevent long passwords from overlapping with the absolute-positioned toggle.
**Action:** When implementing this pattern, always add `padding-right` (e.g., `3.5rem`) to the input field and wrap it in a `position: relative` container with `margin-bottom` applied to the container rather than the input to maintain layout consistency.
