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

Currently, performance on an M2 MacBook Air measured using Instruments looks like this:

| Mode | Cost Factor | Hash Time (ms) |
|------|-------------|-----------------|
| Release | 12 | 195ms |
| Debug | 12 | 453ms |
    
