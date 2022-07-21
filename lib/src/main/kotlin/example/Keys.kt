package crypto.curve25519.example.keys

import crypto.curve25519.*

data class SecretKey(val fe: FieldElement) {
    companion object {
        fun random() = SecretKey(FieldElement.random())
    }

    val publicKey = PublicKey(fe * Curve.basePoint)
}

data class PublicKey(val ge: GroupElement)
