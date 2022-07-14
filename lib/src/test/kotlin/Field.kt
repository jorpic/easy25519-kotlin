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
}
