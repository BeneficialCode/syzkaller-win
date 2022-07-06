# syzkaller - kernel fuzzer

[![CI Status](https://github.com/google/syzkaller/workflows/ci/badge.svg)](https://github.com/google/syzkaller/actions?query=workflow/ci)
[![OSS-Fuzz](https://oss-fuzz-build-logs.storage.googleapis.com/badges/syzkaller.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?q=label:Proj-syzkaller)
[![Go Report Card](https://goreportcard.com/badge/github.com/google/syzkaller)](https://goreportcard.com/report/github.com/google/syzkaller)
[![Coverage Status](https://codecov.io/gh/google/syzkaller/graph/badge.svg)](https://codecov.io/gh/google/syzkaller)
[![GoDoc](https://godoc.org/github.com/google/syzkaller?status.svg)](https://godoc.org/github.com/google/syzkaller)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

`syzkaller` (`[siːzˈkɔːlə]`) is an unsupervised coverage-guided kernel fuzzer.\
Only Supported OS: `Windows`.

![syz_web](docs/syz_web.png)

![syz_manager](docs/syz_manager.png)

![syz_vm](docs/syz_vm.png)

Mailing list: [syzkaller@googlegroups.com](https://groups.google.com/forum/#!forum/syzkaller) (join on [web](https://groups.google.com/forum/#!forum/syzkaller) or by [email](mailto:syzkaller+subscribe@googlegroups.com)).

Found bugs: [Windows](docs/windows/README.md).

## Documentation

Initially, original syzkaller was developed with Linux kernel fuzzing in mind, but now
it's being extended to support Windows kernels as well.
Most of the documentation at this moment is related to the [Windows](docs/windows/README.md) kernel.

- [How to install syzkaller](docs/setup.md)
- [How to use syzkaller](docs/usage.md)
- [How syzkaller works](docs/internals.md)
- [How to contribute to syzkaller](docs/contributing.md)
- [Tech talks and articles](docs/talks.md)
- [Research work based on syzkaller](docs/research.md)

## Disclaimer

This is not an official Google product.
