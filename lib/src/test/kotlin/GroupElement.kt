package crypto.curve25519

import kotlin.test.Test
import kotlin.test.assertTrue

class GroupElementTest {
    @Test fun groupArithmetics() {
        val G = Curve.basePoint
        val two = FieldElement.fromLong(2)
        val three = FieldElement.fromLong(3)
        val x = FieldElement.random()
        val y = FieldElement.random()

        assertTrue(G + G - G == G)
        assertTrue((two + three) * G == three * G + two * G)
        assertTrue((x + y) * G == x * G + y * G)
        assertTrue((x * y + x + y) * G == (x * y) * G + x * G + y * G)
        // assertTrue((x * y) * G == x * (y * G))
    }
}
