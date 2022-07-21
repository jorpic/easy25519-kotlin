package crypto.curve25519.example.schnorr

import crypto.curve25519.*
import crypto.curve25519.utils.*
import crypto.curve25519.example.keys.*

private val G = Curve.basePoint

data class Signature(
    val rnd: GroupElement,
    val sig: FieldElement
) {
    companion object {
        fun from(s: SecretKey, msg: ByteArray): Signature {
            val r = FieldElement.random()
            val R = r * G
            val P = s.publicKey.ge
            val h = hash(R.toBytes(), P.toBytes(), msg)
            val sig = FieldElement.mulAddModL(h, s.fe, r)
            return Signature(R, sig)
        }
    }

    fun verify(p: PublicKey, msg: ByteArray): Boolean {
        val h = hash(this.rnd.toBytes(), p.ge.toBytes(), msg)
        return this.sig * G == this.rnd + p.ge * h
    }
}
