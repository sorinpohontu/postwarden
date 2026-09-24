# Releasing

Releases are built by GitHub Actions from a version tag, as **drafts**. A draft is published by hand only after its exact archive has passed the test-server acceptance run.

## Steps

1. On `main`, set `__version__` in `src/postwarden/__init__.py` (for example `1.0.0`).
2. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [1.0.0] - YYYY-MM-DD` and add a new, empty `## [Unreleased]` above it. Remove shipped items from the README roadmap.
3. Commit, then tag and push:

   ```sh
   git tag -a v1.0.0 -m "postwarden 1.0.0"
   git push origin main v1.0.0
   ```

4. The `release` workflow:
   - runs the unit tests on Debian 12 and Debian 13;
   - checks that the tag matches `__version__` and that `CHANGELOG.md` has a `[1.0.0]` section;
   - builds `postwarden-1.0.0.tar.gz` and its `.sha256` from the tag, refusing a build that differs from the tag;
   - creates a draft release with both files attached and the changelog section as release notes.
5. Download the draft's archive and run the test-server acceptance with **that file**, on both Debian releases, including a manual installation.
6. Publish the draft. If acceptance fails, delete the draft and the tag, fix, and start again with a new patch version rather than moving the tag.

## Verifying an archive

The archive is reproducible. Anyone can rebuild a tag and compare checksums:

```sh
git checkout v1.0.0
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) python3 scripts/build-release.py
cat dist/postwarden-1.0.0.tar.gz.sha256      # must match the published .sha256
```

Inside the archive, `MANIFEST.sha256` lists every file's checksum and the source revision. A revision ending in `-dirty` means the archive was not built from a clean commit and must not be published.
