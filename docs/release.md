Release procedure
=================

This document describes how to release a new version.

## Versioning

Follow [semantic versioning 2.0.0][semver] to choose the new version number.

## Bump version

1. Go to Actions on GitHub Web UI and select Release job.
2. Run the workflow with an appropriate version number.

GitHub actions will build and push artifacts such as container images and
create a new GitHub release.

[semver]: https://semver.org/spec/v2.0.0.html
[example]: https://github.com/cybozu-go/etcdpasswd/commit/77d95384ac6c97e7f48281eaf23cb94f68867f79
