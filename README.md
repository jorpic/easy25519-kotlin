This library is a thin wrapper over the core part of the
[ed25519-java](https://github.com/str4d/ed25519-java) library.

Main motivation was to provide typeful curve primitives that enforce safe
operations at compile time instead of throwing exception at runtime.

Type-level representation tracking
----------------------------------

[ed25519-java](https://github.com/str4d/ed25519-java) allows several
representations of group elements on a curve and user is requred to carefully
track element's representation and insert suitable conversions.

For example, to add two group elements we need one of them to be in `P3`
representation, and the other one in `CACHED` representation. And the result
of such addition is a group element in `P1P1` representation.

Here is how to triple some element assuming it is in `P3` rep:

```kotlin
fun triple(x: GroupElement) = x.add(x.toCached()).toP3().add(x.toCached())
```

Missing any of `toXX` functions here will result in `IllegalArgumentException`.


`easy25519` adds type-level tags to track element representation at compile
time. We also use Kotlin's ability to overload operators for clarty.

```kotlin
fun <C: Curve<*>> triple(x: GroupElement<C, Rep.P3>) : GroupElement<C, Rep.P1P1>
    = (x + x.toCached()).toP3() + x.toCached()
```

This code requires the same conversions, but now missing any fo them will
result in compile-time error like this:

```
Type mismatch: inferred type is GroupElement<C, Rep.P3> but GroupElement<TypeVariable(C), Rep.CACHED> was expected
```


Universal representation
------------------------

We also provide "Universal representation" which works by automatically
inserting representation conversions at runtime. Together with Kotlin's
operator overloading feature this allows for the cleanest code.

```kotlin
fun <C: Curve<*>> triple(x: GroupElement<C, Rep.U>) : GroupElement<C, Rep.U>
    = x + x + x
```
