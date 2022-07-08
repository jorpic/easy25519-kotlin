package crypto.curve25519.utils

import crypto.curve25519.math.*
import net.i2p.crypto.eddsa.math.ed25519.Ed25519ScalarOps
import java.security.MessageDigest
import java.util.Random


val G = Curve25519.basePoint.toUniversal()

fun hash(vararg msg: ByteArray): ByteArray {
    val md = MessageDigest.getInstance("SHA-512")
    msg.forEach {
        md.update(it)
    }
    return Ed25519ScalarOps().reduce(md.digest())
}


fun <F: Field> randomFieldElement(f: F): FieldElement<F> = ByteArray(32).let {
    rnd.nextBytes(it)
    it[31] = (it[31].toInt() and 0x3f).toByte()
    FieldElement.fromBytesLE(f, it)
}

val rnd = Random()
