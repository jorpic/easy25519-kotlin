package crypto.curve25519.math

import kotlin.test.Test
import kotlin.test.assertTrue

class MathTest {
    @Test fun fieldArithmetics() {
        val one: FieldElement<GF25519> = FieldElement.fromLong(GF25519, 1L)
        val two = FieldElement.fromLong(GF25519, 2L)
        val three = FieldElement.fromLong(GF25519, 3L)

        assertTrue(one + two == three, "add")
        assertTrue(three - one == two, "subtract")
        assertTrue(two + two == two * two, "multiply")
        assertTrue((two + two) / two == two, "divide")
        assertTrue(three + two == (three * three + one) / two, "arithmetics")
    }

    @Test fun groupArithmetics() {
        val b: GroupElement<Curve25519, Rep.P3> = Curve25519.basePoint
        val three = FieldElement.fromLong(GF25519, 3L)

        assertTrue(three * b == (b + b.toCached()).toP3() + b.toCached(), "add")
        assertTrue(three * b == b * three, "add")
    }

    @Test fun universalRepresentation() {
        val b: GroupElement<Curve25519, Rep.U> = Curve25519.basePoint.toUniversal()
        val three = FieldElement.fromLong(GF25519, 3L)

        assertTrue(three * b == b + b + b, "add")
    }
}
