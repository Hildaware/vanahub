# VanaHub public catalog repository template

This directory is copied into a separate hardened repository. The product
source and public package-submission history intentionally do not share a Git
repository.

Before enabling workflows:

1. Replace `OWNER/PRODUCT_REPOSITORY` and `PINNED_PRODUCT_COMMIT` with the
   product repository and an immutable reviewed commit.
2. Configure branch protection and allow auto-merge only after `admission`.
3. Add `VANAHUB_ED25519_PRIVATE_KEY` as a protected Actions secret containing a
   base64-encoded 32-byte Ed25519 seed.
4. Replace the placeholder public key in the product and publish a client
   release before signing production indexes.
5. Enable GitHub Pages deployment from Actions.

Routine package PRs may change exactly one `packages/<id>/manifest.json`.
Workflow, policy, schema, revocation, and signing changes require catalog
administrator review.

`packages/example/manifest.example.json` is documentation only. Copy it to a
new `packages/<real-id>/manifest.json` and replace every placeholder when
submitting the first real package.
