# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.0.0] - 2026-03-20

### Added
- Initial release of reporium-security
- Security scanning for all Reporium repos: secrets, CVEs, workflows, files, and git history
- Reusable test failure workflow via perditio-devkit

### Fixed
- Handle encoding errors in git history scanning
- Skip test fixtures and placeholder files during scans
