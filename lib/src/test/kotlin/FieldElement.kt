package crypto.curve25519

import kotlin.test.Test
import kotlin.test.assertTrue

class FieldElementTest {
    @Test fun fieldArithmeticsWithSmallNumbers() {
        val one = FieldElement.fromLong(1)
        val two = FieldElement.fromLong(2)
        val three = FieldElement.fromLong(3)

        assertTrue(one + two == three)
        assertTrue(three - one == two)
        assertTrue(two + two == two * two)
        assertTrue((two + two) / two == two)
        assertTrue(three + two == (three * three + one) / two)
    }

    @Test fun fieldArithmeticsWithRandomNumbers() {
        val x = FieldElement.random()
        val y = FieldElement.random()
        val z = FieldElement.random()
        val one = FieldElement.fromLong(1)

        assertTrue(x + x + x  == x * (one + one + one))
        assertTrue((x + y)*z == y*z + x*z)
        assertTrue((x * y * z) / y == x * z)
    }
}
