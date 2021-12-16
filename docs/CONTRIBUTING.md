## Guidelines for submitting bugs

All non security bugs can be filed on the Issues tracker:

<https://github.com/tpm2-software/tpm2-pkcs11/issues>

Security sensitive bugs should be emailed to a maintainer or to Intel
via the guidelines here:

<https://security-center.intel.com/VulnerabilityHandlingGuidelines.aspx>

## Guidelines for submitting changes

All changes should be introduced via GitHub pull requests. This allows anyone to
comment and provide feedback in lieu of having a mailing list. For pull requests
opened by non-maintainers, any maintainer may review and merge that pull request.
For maintainers, they either must have their pull request reviewed by another
maintainer if possible, or leave the PR open for at least 24 hours, we consider
this the window for comments.

  * All tests must pass on Github Actions CI for the merge to occur.
  * All changes must not introduce superfluous whitespace changes or whitespace errors.
  * All changes should adhere to the coding standard documented under misc.

## Testing
The Github Actions setup uses a docker container, thus this docker container can be used
to run the CI testing before submitting. The rationale for using a container versus
Docker directly is that:
1. Debugging build failures on Github Actions can be frustrating
2. Github Actions doesn't have support for many distributions and versions. With a container
   we can trivially add additional distro testing.

### How To Run Docker Locally

You need to have the docker tools installed and this is not meant to be a full docker
tutorial. Docker installation and usage information can be found here:
  - https://www.docker.com/

You can either test with CC set to gcc or clang. It is not recommended to specify versions
as the container may change compiler versions and reconfigure the default at any time. If
CC is empty, it defaults to gcc. It is recommended to test with both as they perform different
tests, such as `scan-build` and `asan` based unit testing.

**Note**: We assume that all commands are run from the tpm2-pkcs11 repo checkout directory.

To test with a compiler do:
```sh
# either gcc or clang
export CC=clang
docker run --env-file .ci/docker.env -v `pwd`:/workspace/tpm2-pkcs11 tpm2software/tpm2-tss /bin/bash -c /workspace/tpm2-pkcs11/.ci/coverity.run
```

If one wishes to test multiple compilers, it's advantageous to enter the docker
container and set CC before invoking the `coverity.run` script. It won't resync,
build and install the tpm2-tss, tpm2-abrmd and tpm2-tools dependencies on multiple
invocations, thus saving time, for example:
```sh
docker run -it --env-file .ci/docker.env -v `pwd`:/workspace/tpm2-pkcs11 tpm2software/tpm2-tss
export CC=gcc
/workspace/tpm2-pkcs11/.ci/coverity.run
export CC=clang
/workspace/tpm2-pkcs11/.ci/coverity.run
```

## Guideline for merging changes

Pull Requests MUST be assigned to an upcoming release tag. If a release milestone does
not exist, the maintainer SHALL create it per the [RELEASE.md](RELEASE.md) instructions.
When accepting and merging a change, the maintainer MUST edit the description field for
the release milestone to add the CHANGELOG entry.

Changes must be merged with the "rebase" option on github to avoid merge commits.
This provides for a clear linear history.
