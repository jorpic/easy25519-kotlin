package crypto.curve25519.utils

import java.security.MessageDigest
import java.util.Random
import crypto.curve25519.math.curve.Curve25519
import crypto.curve25519.math.field.GF25519ModL
import crypto.curve25519.math.group.*
import crypto.curve25519.math_old.Field
import crypto.curve25519.math_old.FieldElement


val G = Curve25519.basePoint
val H = (GF25519ModL.fromLong(123) * G).eval()

fun hash(vararg msg: ByteArray): GF25519ModL {
    val md = MessageDigest.getInstance("SHA-512")
    msg.forEach {
        md.update(it)
    }
    return GF25519ModL.fromBytes64(md.digest())
}

fun <F: Field> randomFieldElement(f: F): FieldElement<F> = ByteArray(32).let {
    rnd.nextBytes(it)
    it[31] = (it[31].toInt() and 0x3f).toByte()
    FieldElement.fromBytesLE(f, it)
}

val rnd = Random()
