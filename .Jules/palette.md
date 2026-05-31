## 2026-05-17 - Missing Input Labels in Core Authentication and Dashboard Forms
**Learning:** Discovered a consistent pattern of missing `<label>` elements for form inputs in the Svelte routes (`login`, `dashboard`). This degrades accessibility for screen reader users and makes the UI less intuitive for keyboard navigation.
**Action:** Always ensure every form `<input>` has an associated `<label>` using the `id` and `for` attributes. For secondary actions like switching between login and registration, use buttons with clear descriptive text or ARIA roles rather than just separate buttons.

## 2026-05-22 - Build Failures and UX Constraints
**Learning:** Production builds in this SvelteKit environment are sensitive to Vite configuration and dependency versions. Specifically, 'manualChunks' for 'axios' and incompatible versions of '@sveltejs/vite-plugin-svelte' cause immediate build failures.
**Action:** Prioritize build stability over non-essential optimizations (like manual chunking) and ensure all UX improvements are verified with 'pnpm build' in a clean environment.

## 2026-05-25 - Enhancing Async Feedback and Control
**Learning:** Initial feedback after job submission was slightly delayed until the first poll returned. Using `<output aria-live="polite">` for status messages and providing a way to "Clear" the dashboard state significantly improves the user's sense of control and accessibility.
**Action:** Always provide immediate 'pending' feedback for async tasks and include 'Clear' or 'Reset' actions for ephemeral dashboard results. Use semantic `<output>` for dynamic status text.

## 2026-05-28 - Utility Features for Sandbox Testing
**Learning:** Adding 'Randomize' or 'Auto-fill' buttons in developer-focused sandbox environments (like a Homomorphic Encryption demo) significantly reduces user friction during repetitive testing and improves the overall experience by providing instant, valid data points.
**Action:** Identify interactive input-heavy areas in sandbox tools and offer randomization utilities to streamline the user workflow.
