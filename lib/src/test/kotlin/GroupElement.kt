package crypto.curve25519

import kotlin.test.Test
import kotlin.test.assertTrue
import crypto.curve25519.utils.decodeHex

class GroupElementTest {
    @Test fun groupArithmetics() {
        val G = Curve.basePoint
        val two = ModL.fromLong(2)
        val three = ModL.fromLong(3)
        val x = FieldElement.random()
        val y = FieldElement.fromBytesLE(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f"
            .decodeHex()
        )

        assertTrue(G + G - G == G)
        assertTrue(y * G == ModL(y) * G)
        assertTrue((two + three) * G == three * G + two * G)
        assertTrue((x + y) * G == x * G + y * G)
        assertTrue(ModL.mulAdd(x, y, x + y) * G == ModL.mul(x, y) * G + x * G + y * G)
        assertTrue(ModL.mul(x, y) * G == x * (y * G))
    }
}
