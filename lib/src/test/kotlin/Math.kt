package crypto.curve25519.math

import kotlin.test.Test
import kotlin.test.assertTrue

class MathTest {
    @Test fun fieldArithmeticsWithSmallNumbers() {
        val one: FieldElement<GF25519> = FieldElement.fromLong(GF25519, 1L)
        val two = FieldElement.fromLong(GF25519, 2L)
        val three = FieldElement.fromLong(GF25519, 3L)

        assertTrue(one + two == three)
        assertTrue(three - one == two)
        assertTrue(two + two == two * two)
        assertTrue((two + two) / two == two)
        assertTrue(three + two == (three * three + one) / two)
    }

    @Test fun fieldArithmetics() {
        val x = FieldElement.random(GF25519)
        val y = FieldElement.random(GF25519)
        val z = FieldElement.random(GF25519)
        val three = FieldElement.fromLong(GF25519, 3L)

        assertTrue(x + x + x == three * x)
        assertTrue(x + x == three * x - x)
        assertTrue((x + x + x) / x == three)
        assertTrue((x + y) * z == x*z + y*z)
    }

    @Test fun groupArithmeticsWithSmallNumbers() {
        val b: GroupElement<Curve25519, Rep.P3> = Curve25519.basePoint
        val three = FieldElement.fromLong(GF25519, 3L)

        assertTrue(three * b == (b + b.toCached()).toP3() + b.toCached())
        assertTrue(three * b == b * three)
    }

    @Test fun universalRepresentation() {
        val b: GroupElement<Curve25519, Rep.U> = Curve25519.basePoint.toUniversal()
        val x = FieldElement.random(GF25519)
        val y = FieldElement.random(GF25519)

        assertTrue(x * b + y * b == (x + y) * b)
        assertTrue((x * y) * b == x * (y * b))
        assertTrue((y * x) * b == x * (y * b))
        assertTrue(x * (y * b) == y * (x * b))
    }
}
