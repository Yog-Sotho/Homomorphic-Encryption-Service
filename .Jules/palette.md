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

## 2026-06-15 - Enhancing Password Field Usability and Verification
**Learning:** Standardizing password inputs with visibility toggles and dynamic `autocomplete` attributes (`current-password` vs `new-password`) significantly reduces friction during authentication. When verifying these with Playwright, the `get_by_label` locator with `exact=True` is crucial to avoid collisions between the input and the toggle button's `aria-label`.
**Action:** Always implement password visibility toggles with appropriate `aria-label` and `autocomplete` hints. Use `exact=True` in Playwright tests to target specific labeled elements when ARIA labels overlap.
