# NetBrief project map for Obsidian

`NetBrief-Project-Map.canvas` is a self-contained, editable Obsidian Canvas.
It contains 38 text cards in eight sections, with arrows for the current
runtime flow, proposed component interfaces, and development priorities.

## Open it in Obsidian

1. Download `NetBrief-Project-Map.canvas` using GitHub's **Download raw file**
   button. Keep the `.canvas` extension; do not save the GitHub HTML page.
2. Copy the file into your Obsidian vault, for example `Projects/NetBrief/`.
3. Open it from Obsidian's file explorer. Use **Zoom to fit**, then zoom into
   individual sections. Read sections 01–08 from top to bottom.

No community plugin, accompanying note, or repository checkout is required.
All card text is embedded in the Canvas file. Cards can be edited and moved.

## Reading the map

- **01 — Product:** Purpose, audience, workflow, scope, and legend.
- **02 — Runtime:** Capture upload through parsing, analysis, dashboard, and export.
- **03 — Implementation:** Repository structure, API, startup, formats, and decoding.
- **04 — Results:** Report contract, dashboard, SYN heuristic, sample, and tests.
- **05 — Limitations:** Reproduced defects, upload/resource risks, and completeness.
- **06 — Proposed architecture:** Incremental module boundaries and stable contracts.
- **07 — v0.2 plan:** Eight ordered tasks with completion criteria.
- **08 — Future roadmap:** Detection expansion, investigation UX, integrations, and stability.

Green cards describe current implementation; red cards describe limitations;
purple cards describe proposals; orange cards describe next tasks. Status is
also written in the card text so the map does not depend on color alone.

The current-code baseline is commit `4816cbd`. The verification notes refer to
the initial assessment and branding-change test runs, not to exhaustive format,
Windows, browser, or security testing. Future features are explicitly marked
as proposed and are not claims of implemented functionality.
