# Swift Bcrypt

A native, dependency and Foundation free Swift implementation of the bcrypt password hashing algorithm, based on the [OpenBSD implementation](https://github.com/openbsd/src/blob/master/lib/libc/crypt/bcrypt.c).

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
let hash = try Bcrypt.hash(password: password)
let isValid = try Bcrypt.verify(password: password, hash: hash)
```

## Performance

Currently these are the benchmarks for hashing the password "password" with cost factor 12, compared to Vapor's C Bcrypt implementation. Measurements were taken on an M2 MacBook Air.

| | Release ms | Debug ms | Allocations Release | Allocations Debug |
|------|------------|----------|---------------------|-------------------|
| vapor/authentication | 215ms | 337ms | ~13,700 | ~13,800 |
| swift-bcrypt | 195ms | 453ms | ~13,400 | ~13,500 |

    
