# Swift Bcrypt

A native, dependency and Foundation free Swift implementation of the bcrypt password hashing algorithm, based on the [OpenBSD implementation](https://github.com/openbsd/src/blob/master/lib/libc/crypt/bcrypt.c).

> [!WARNING]
> This package is not yet ready for production use. It is still in development and has not been thoroughly tested.

## Installation

```swift
.package(url: "https://github.com/ptoffy/swift-bcrypt.git", branch: "main")
```

```swift
.product(name: "Bcrypt", package: "bcrypt")
```

## Usage

```swift
import Bcrypt

let password = "password"
let hash = try Hasher(version: .v2a).hash(password: password)
```

