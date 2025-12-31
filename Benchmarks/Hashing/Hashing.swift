import Bcrypt
import Benchmark

let benchmarks = {
    Benchmark.defaultConfiguration = .init(
        metrics: [.mallocCountTotal, .wallClock]
    )

    Benchmark("Hash 12") { benchmark in
        try Bcrypt.hash(password: "password", cost: 12)
    }
}
