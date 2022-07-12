package crypto.curve25519.utils

import crypto.curve25519.math.*
import net.i2p.crypto.eddsa.math.ed25519.Ed25519ScalarOps
import java.security.MessageDigest
import java.util.Random


val G = Curve25519.basePoint.toUniversal()

// Another base point is required in some algorithms (e.g. Pedersen
// commitments).
// FIXME: It must be independent from the G.
// I.e. it should be impossible to find such x and y that x * G = y * H.
val H: GroupElement<Curve25519, Rep.U> = G * FieldElement.fromLong(GF25519, 123L)


fun hash(vararg msg: ByteArray): FieldElement<GF25519> {
    val md = MessageDigest.getInstance("SHA-512")
    msg.forEach {
        md.update(it)
    }
    return FieldElement.fromBytesLE(
        GF25519,
        Ed25519ScalarOps().reduce(md.digest())
    )
}


fun <F: Field> randomFieldElement(f: F): FieldElement<F> = ByteArray(32).let {
    rnd.nextBytes(it)
    it[31] = (it[31].toInt() and 0x3f).toByte()
    FieldElement.fromBytesLE(f, it)
}

val rnd = Random()
