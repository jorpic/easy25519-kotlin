package crypto.curve25519.utils

import crypto.curve25519.math.*
import net.i2p.crypto.eddsa.math.ed25519.Ed25519ScalarOps
import java.security.MessageDigest
import java.util.Random


val G = Curve25519.basePoint.toUniversal()

fun hash(msg: ByteArray): ByteArray {
    val md = MessageDigest.getInstance("SHA-512")
    val h = Ed25519ScalarOps().reduce(md.digest(msg))
    // FIXME: FE cutoff
    for(i in 15..31) {
        h[i] = 0
    }
    return h
}


// FIXME: FE cutoff
fun <F: Field> randomFieldElement(f: F): FieldElement<F> = ByteArray(32).let {
    for (j in 0..14) {
        it[j] = rnd.nextInt(0x100).toByte()
    }
    FieldElement.fromBytesLE(f, it)
}

val rnd = Random()
