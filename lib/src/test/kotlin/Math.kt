package crypto.curve25519.math_old

import kotlin.test.Test
import kotlin.test.assertTrue

val G = Curve25519.basePoint.toUniversal()


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
        val x = FieldElement.random(GF25519)
        val y = FieldElement.random(GF25519)

        assertTrue(x * G + y * G == (x + y) * G)
        assertTrue(x * (y * G) == y * (x * G))
        assertTrue(GF25519.mul(x, y) * G == x * (y * G))
        assertTrue(GF25519.mul(y, x) * G == y * (x * G))
    }
}
