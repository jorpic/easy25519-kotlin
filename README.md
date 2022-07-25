This library is a thin wrapper over the core part of the
[ed25519-java](https://github.com/str4d/ed25519-java) library.

Main motivation was to provide primitives that enforce safe operations instead
of throwing exceptions at runtime.

[ed25519-java](https://github.com/str4d/ed25519-java) provides several
representations of group elements on the curve and user is requred to carefully
track element's representation and insert suitable conversions.

For example, to add two group elements we need one of them to be in `P3`
representation, and the other one in `CACHED` representation. And the result
of such addition is a group element in `P1P1` representation.

Here is how to triple some element assuming it is in `P3` rep:

```kotlin
fun triple(x: GroupElement) = x.add(x.toCached()).toP3().add(x.toCached())
```

Missing any of `toXX` functions here will result in `IllegalArgumentException`.


`easy25519` takes responsibility of tracking element representation. We also
use Kotlin's ability to overload operators for clarty.

```kotlin
fun triple(x: GroupElement) : GroupElement = x + x + x
```

Examples
--------

There are toy implementations of:
  - [Schnorr signatures](lib/src/main/kotlin/example/Schnorr.kt)
  - [Pedersen commitments](lib/src/main/kotlin/example/Pedersen.kt)
  - [Mimblewimble protocol](lib/src/main/kotlin/example/Mimblewimble.kt)
