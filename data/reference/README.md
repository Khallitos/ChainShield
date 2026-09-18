# Standard reference lists

| File | Source | Licence | Snapshot |
|---|---|---|---|
| `guarddog_top_npm_packages.json` | DataDog GuardDog, `guarddog/analyzer/metadata/resources/top_npm_packages.json` (commit `632031f5b5`, 2026-06-16) | Apache-2.0 | 8,000 most popular npm packages, downloaded 2026-05 (field `downloaded_timestamp`) |

Used as the popular-name reference for typosquatting distance (features `min_edit_distance`,
`typosquat_high`). It is a similarity reference only: a name on this list is **not** trusted by the
project; trust comes from the scanned project's own lockfile.
5dca2af07632c2ece46ca11fefaaa836988a9fade8af8120ed77f2f0712f9127 *guarddog_top_npm_packages.json
