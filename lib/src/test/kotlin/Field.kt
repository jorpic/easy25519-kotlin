package crypto.curve25519.math

import kotlin.test.Test
import kotlin.test.assertTrue
import crypto.curve25519.math.field.*

class FieldTest {
    @Test fun test() {
        val x: GF25519 = GF25519.fromLong(2L)
        val y: GF25519ModL = GF25519.fromLong(2L)
        val z: GF25519ModL = GF25519ModL.fromLong(2L)
    }
    @Test fun fieldArithmeticsWithSmallNumbers() {
        val one = GF25519.fromLong(1L)
        val two = GF25519.fromLong(2L)
        val three = GF25519.fromLong(3L)

        assertTrue((one + two).eval() == three)
        // assertTrue(three - one == two)
        println(two.toHex())
        println((two + two).eval().toHex())
        println((two * two).eval().toHex())
        assertTrue(two + two == two * two)
        // assertTrue((two + two) / two == two)
        // assertTrue(three + two == (three * three + one) / two)
    }
}
