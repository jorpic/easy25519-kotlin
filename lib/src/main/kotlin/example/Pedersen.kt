package crypto.curve25519.example.pedersen

import crypto.curve25519.*

val G = Curve.basePoint
// FIXME: this point must be independent from G
val H = G * ModL.fromLong(123)

data class Commitment(
    val ge: GroupElement
) {
    companion object {
        fun fromValue(v: Long, key: FieldElement)
            = Commitment(ModL.fromLong(v) * H + key * G)
    }

    operator fun plus(c: Commitment) = Commitment(this.ge + c.ge)
    operator fun minus(c: Commitment) = Commitment(this.ge - c.ge)
}
