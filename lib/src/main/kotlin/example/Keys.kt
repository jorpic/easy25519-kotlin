package crypto.curve25519.example.keys

import crypto.curve25519.math.curve.Curve25519
import crypto.curve25519.math.field.GF25519
import crypto.curve25519.math.group.CurveGroup
import crypto.curve25519.math.group.times
import crypto.curve25519.utils.*


data class SecretKey(val fe: GF25519) {
    companion object {
        fun random() = SecretKey(GF25519.random())
    }

    val publicKey = PublicKey((fe * Curve25519.basePoint).eval())
}

data class PublicKey(val ge: CurveGroup)
