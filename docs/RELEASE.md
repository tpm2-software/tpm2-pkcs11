# Release Information

Releases shall be tagged following semantic version guidelines found at:

- <http://semver.org/>

The general release process will be one of two models:

- Tag releases off of branch master.
- Tag releases off of a release specific branch.
  - Release specific branch names can be for long-running major versions, IE 3.1, 3.2, 3.3, etc.
    and *SHALL* be named `<major-version>.X`.
  - Release specific branch names can be for long-running minor versions, IE 3.1.1, 3.1.2, etc.
    and *SHALL* be named `<major-version>.<minor-version>.X`.

Release candidates will be announced on the
[mailing list](https://lists.01.org/mailman/listinfo/tpm2). When a RC has gone 1
week without new substantive changes, a release will be conducted. Substantive
changes are generally not editorial in nature and they do not contain changes to
the CI system. Substantive changes are changes to the man-pages, code or tests.

When a release is cut, the process is the same as a Release Candidate (RC), with the exception that
it is not marked as "pre-release" on GitHub. The release notes should include everything from the
last release to the latest release.

## Updating the CHANGELOG for release candidates and final releases

When a first release candidate is cut, a new entry will be added to the CHANGELOG file. This
entry will have the release candidate version and the date on which the release candidate was
released. The entry will list all the changes that happened between the latest final release
and the first release candidate.

The commit that made the change will be tagged with a release version and a -rc0 suffix as an
indication that is not a final release but a first release candidate. If after a week the -rc
has no changes, then a final release can be made as explained above. But if changes are made,
then a new releases candidate will be released and the -rc suffix will be incremented.

For each release candidate, the changes that happened between the previous release candidate
will be appended to the CHANGELOG entry, and both the release candidate version and the date
of the release will be updated to reflect the latest release candidate.

The commit that updated the CHANGELOG entry will be tagged as the latest release candidate.

When a final version will be released, there will not be changes to append to the CHANGELOG
entry since otherwise a new release candidate should be cut. So only the release version and
date should be updated in the CHANGELOG.

The commit that updated the CHANGELOG entry will be tagged as the final release.

For a final release, change the version to the final release version (i.e: 3.0.5-rc3 -> 3.0.5) and
update the date. The commit for this change will be tagged as $version.

## Testing

The tools code **MUST** pass the Github Actions testing and have a clean
Coverity scan result performed on every release. The CI testing not
only tests for valid outputs, but also runs tests uses clang's ASAN
feature to detect memory corruption issues.

## Release Checklist

The steps, in order, required to make a release.

- Ensure current HEAD is pointing to the last commit in the release branch.

- Ensure [GitHub Actions](https://github.com/tpm2-software/tpm2-pkcs11/actions)
  has conducted a passing build of HEAD.

- Update version and date information in [CHANGELOG.md](CHANGELOG.md) **and** commit.

- Create a signed tag for the release. Use the version number as the title line in the tag commit
  message and use the [CHANGELOG.md](CHANGELOG.md) contents for that release as the body.
  ```bash
  git tag -s <tag-name>
  ```

- Build a tarball for the release and check the dist tarball. **Note**: The file name of the tarball
  should include a match for the git tag name.
  ```bash
  make distcheck
  ```

- Generate a detached signature for the tarball.
  ```bash
  gpg --armor --detach-sign <tarball>
  ```

- Push **both** the current git HEAD (should be the CHANGELOG edit) and tag to the release branch.
  ```bash
  git push origin HEAD:<release-branch>
  git push origin <tag-name>
  ```

- Verify that the GitHub Actions build passes.
  **Note**: GitHub Actions will have two builds, one for the push to master and one for the tag push.
  Both should succeed.

- Create a release on [Github](https://github.com/tpm2-software/tpm2-pkcs11/releases),
  using the `<release-tag>` uploaded. If it is a release candidate, ensure you check the "pre-release"
  box on the GitHub UI. Use the [CHANGELOG.md](CHANGELOG.md) contents for
  that release as the message for the GitHub release. **Add the dist tarball and signature file
  to the release**.

- Update the version matrix in the wiki ensuring that the CI is building against a released version of:
  - [tpm2-abrmd](https://github.com/tpm2-software/tpm2-abrmd)
  - [tpm2-tss](https://github.com/tpm2-software/tpm2-tss)

  Configuration can be modified via [docker-prelude.sh](.ci/docker-prelude.sh).

- After the release (not a release candidate) add a commit to master updating the News section of
  the [README](README.md) to point to the latest release.

- Send announcement on [mailing list](https://lists.01.org/mailman/listinfo/tpm2).

## Verifying git signature

Valid known public keys can be reached via a PGP public keyring server like:

- <http://keyserver.pgp.com/vkd/GetWelcomeScreen.event>
- <https://keyserver.ubuntu.com/>

**Example** for William Roberts (key [`5B482B8E3E19DA7C978E1D016DE2E9078E1F50C1`](https://keyserver.ubuntu.com/pks/lookup?search=0x5B482B8E3E19DA7C978E1D016DE2E9078E1F50C1&fingerprint=on&op=index):

```bash
curl 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x5b482b8e3e19da7c978e1d016de2e9078e1f50c1' | \
  gpg --import
```

Verify the release tag:

```bash
git tag --verify [signed-tag-name]
```

# Local Release Configuration

Below you will find information how to configure your machine locally to conduct releases.

## Signing Key Setup

Signing keys should have these four properties going forward:
  - belong to a project maintainer.
  - be discoverable using a public GPG key server.
  - be [associated](https://help.github.com/articles/adding-a-new-gpg-key-to-your-github-account/)
    with the maintainers GitHub account.
  - be discoverable via an annotated tag within the repository itself.

Ensure you have a key set up:
```bash
gpg --list-keys
```

If you don't generate one:
```bash
gpg --gen-key
```

Add that key to the gitconfig:
```bash
git config user.signingkey [gpg-key-id]
```

Make sure that key is reachable as an object in the repository:
```bash
gpg -a --export [gpg-key-id] | git hash-object -w --stdin [object SHA]
git tag -a [your-name-here]-pub [object SHA]
```

Make sure you push the tag referencing your public key:
```bash
git push origin [your-name-here]-pub
```

Make sure you publish your key by doing:
  - <http://keyserver.pgp.com/vkd/GetWelcomeScreen.event>
    - Select "Publish your key".
    - Select "Key block"
    - Copy and paste the output of `gpg --armor --export <key-id>`
    - Validate your email account.

After that, you can sign tags:
```bash
git tag --sign [signed-tag-name]
```
