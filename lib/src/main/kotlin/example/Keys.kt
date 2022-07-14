package crypto.curve25519.example.keys

import crypto.curve25519.math_old.*
import crypto.curve25519.utils.*


data class SecretKey(val fe: FieldElement<GF25519>) {
    companion object {
        fun random() = SecretKey(FieldElement.random(GF25519))
    }

    val publicKey = PublicKey(fe * Curve25519.basePoint)
}

data class PublicKey(val ge: GroupElement<Curve25519, Rep.U>)
