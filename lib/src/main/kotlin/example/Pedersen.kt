package crypto.curve25519.example.pedersen

import crypto.curve25519.*
import crypto.curve25519.utils.decodeHex

val G = Curve.basePoint
val H = GroupElement.fromBytes(
    // this point was tested with .checkPeriod(40000L)
    "ec405ef496ed99c1c461990cfdb3c6083b0bd1c540d2f89bf8c9accec1a52e42"
    .decodeHex()
)

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
