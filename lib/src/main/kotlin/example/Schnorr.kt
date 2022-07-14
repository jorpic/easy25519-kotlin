package crypto.curve25519.example.schnorr

import crypto.curve25519.math.field.*
import crypto.curve25519.math.group.*
import crypto.curve25519.utils.*
import crypto.curve25519.example.keys.*


data class Signature(
    val rnd: CurveGroup,
    val sig: GF25519ModL
) {
    companion object {
        fun from(s: SecretKey, msg: ByteArray): Signature {
            val r = GF25519.random()
            val R = (r * G).eval()
            val P = s.publicKey.ge
            val h = hash(R.toBytes(), P.toBytes(), msg)
            val sig = r + s.fe * h
            return Signature(R, sig.eval())
        }
    }

    fun verify(p: PublicKey, msg: ByteArray): Boolean {
        val h = hash(this.rnd.toBytes(), p.ge.toBytes(), msg)
        return this.sig * G == this.rnd + h * p.ge
    }
}
