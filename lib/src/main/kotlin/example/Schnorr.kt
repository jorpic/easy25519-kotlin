package crypto.curve25519.example.schnorr

import crypto.curve25519.*
import crypto.curve25519.utils.*
import crypto.curve25519.example.key.*

private val G = Curve.basePoint

data class Signature(
    val rnd: GroupElement,
    val sig: FieldElement
) {
    companion object {
        fun from(s: SecretKey, msg: ByteArray): Signature {
            val r = FieldElement.random()
            val R = r * G
            val h = hash(R.toBytes(), s.publicKey.ge.toBytes(), msg)
            val sig = ModL.mulAdd(h, s.fe, r)
            return Signature(R, sig)
        }
    }

    fun verify(p: PublicKey, msg: ByteArray): Boolean {
        val h = hash(this.rnd.toBytes(), p.ge.toBytes(), msg)
        return this.sig * G == this.rnd + p.ge * h
    }
}
