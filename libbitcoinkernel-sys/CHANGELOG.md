# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- New `btck_block_tree_entry_equals` function for comparing BlockTreeEntry objects (096924d39d64)

### Changed
- `data_directory` and `blocks_directory` parameters in `btck_chainstate_manager_options_create` now allow null values to represent empty paths (6657bcbdb4d0)

## [0.1.1] - 2025-24-11

### Fixed
- Precise package excludes to ensure the test/fuzz directory is included
  in the packaged crate correctly.
