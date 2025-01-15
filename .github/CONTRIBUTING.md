# Contributing capa rules

First off, thanks for taking the time to contribute! :sparkling_heart:

## What should I know before I get started?

### Code of Conduct

This project follows [Google's Open Source Community Guidelines](https://opensource.google/conduct).

### capa and its repositories

We host the capa project as three GitHub repositories:
  - **[capa-rules](https://github.com/mandiant/capa-rules) (this repository)**: The standard rules contributed by the community.
  - **[capa](https://github.com/mandiant/capa)**: The command line tools, logic engine, and other Python source code.
  - **[capa-testfiles](https://github.com/mandiant/capa-testfiles)**: Test fixtures, such as malware samples.

### Documentation

- [README](README.md)
- [rule format page](doc/format.md)

## How Can I Contribute?

### Issues

Open an [issue](https://github.com/mandiant/capa-rules/issues) to share a rules idea and report false positives/negatives. Check the open issues and ensure there is not already a similar issue.

### Code (rule contributions)

Extend and enhance our rule set with a rule contributions based on your own ideas or the [rule-idea](https://github.com/mandiant/capa-rules/issues?q=is%3Aissue+is%3Aopen+label%3A%22rule+idea%22) issues.

#### Before contributing code
Before sending a pull request (PR):

1. Sign the [Contributor License Agreement](#contributor-license-agreement)
2. Ensure each rule passes thorough linting (in rules directory: `python ../scripts/lint.py --thorough -t "<your rule name>" -v .`)
3. [OPTIONAL, but greatly appreciated] Upload each referenced example binary to https://github.com/mandiant/capa-testfiles
4. Please mention the issue your PR addresses (if any) in the PR description:
   ```
   closes https://github.com/mandiant/capa-rules/issues/<issue_number>
   ```

##### Contributor License Agreement

Contributions to this project must be accompanied by a [Contributor License Agreement](https://cla.developers.google.com/about) (CLA).
You (or your employer) retain the copyright to your contribution; this simply gives us permission to use and redistribute your contributions as part of the project.

If you or your current employer have already signed the Google CLA (even if it was for a different project), you probably don't need to do it again.

Visit <https://cla.developers.google.com/> to see your current agreements or to sign a new one.
