package crypto.curve25519.example.pedersen

import crypto.curve25519.math.*
import crypto.curve25519.utils.*


data class Commitment(
    val ge: GroupElement<Curve25519, Rep.U>
) {
    companion object {
        fun fromValue(v: Long, key: FieldElement<GF25519>)
            = Commitment(FieldElement.fromLong(GF25519, v) * H + key * G)
    }

    operator fun plus(c: Commitment) = Commitment(this.ge + c.ge)
    operator fun minus(c: Commitment) = Commitment(this.ge - c.ge)
}
