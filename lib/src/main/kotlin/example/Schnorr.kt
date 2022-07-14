package crypto.curve25519.example.schnorr

import crypto.curve25519.math_old.*
import crypto.curve25519.utils.*
import crypto.curve25519.example.keys.*


data class Signature(
    val rnd: GroupElement<Curve25519, Rep.U>,
    val sig: FieldElement<GF25519>
) {
    companion object {
        fun from(s: SecretKey, msg: ByteArray): Signature {
            val r = FieldElement.random(GF25519)
            val R = r * G
            val P = s.publicKey.ge
            val H = FieldElement.fromBytesLE(
                GF25519,
                hash(R.toBytes(), P.toBytes(), msg)
            )
            val sig = r + GF25519.mul(H, s.fe)
            return Signature(R, sig)
        }
    }

    fun verify(p: PublicKey, msg: ByteArray): Boolean {
        val H = FieldElement.fromBytesLE(
            GF25519,
            hash(this.rnd.toBytes(), p.ge.toBytes(), msg)
        )
        return this.sig * G == this.rnd + p.ge * H
    }
}
