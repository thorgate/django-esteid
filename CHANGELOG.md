# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)


## [4.3] - 2025-04-04
### Added
- `get_nonce` method on `AuthenticationViewMixin` that can be overridden to provide custom nonce
- `login` method on `AuthenticationViewMixin` that allows to invoke django `login` while suppressing 
session key rotation. It is recommended to use this method to avoid `Invalid authentication session` error
on mobile devices with Smart ID app running on same device as the browser running your webapp; however, 
you need to consider security risks.
- Changelog

### Changed
- Upgrade `esteid-helper` to version [0.6.0](https://github.com/thorgate/esteid-helper/releases/tag/0.6.0)
that supports retry on network error
- Persist authentication session state after session completion, including authentication result details.
This allows to execute multiple `patch` requests within the same session, which is useful for example in case
of a network error that causes the FE to never receive the finalization response from BE.
- Persist signing session state after session completion (but not the temporary containers), for same purpose
as with authentication sessions above.

### Fixed
- Use unreleased version of `oscrypto`, dependency of pyasice, that fixes compatibility with some OpenSSL versions,
for tests. If you are getting `oscrypto.errors.LibraryNotFoundError: Error detecting the version of libcrypto` 
in your project you will need to fix your dependencies as well.
- Coverage report including legacy compatibility code scheduled for removal (pragma: no cover not applying properly)
- Exception messages being discarded and default exception message always being used

## [4.3] - 2024-12-31
### Added
- Allow to provide custom random bytes to authenticate

[4.3]: https://github.com/olivierlacan/keep-a-changelog/compare/v4.2...v4.3
[4.2]: https://github.com/olivierlacan/keep-a-changelog/compare/v4.1...v4.2
