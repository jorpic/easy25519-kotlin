package crypto.curve25519.example.schnorr

import kotlin.test.*
import crypto.curve25519.utils.*
import crypto.curve25519.example.key.*

class Schnorr {
    @Test fun signAndCheck() {
        val key1 = SecretKey.random()
        val key2 = SecretKey.random()
        val message1 = "Hello, world!".toByteArray()
        val message2 = "Hello, world?".toByteArray()

        val s1 = Signature.from(key1, message1)

        assertTrue(s1.verify(key1.publicKey, message1))
        assertFalse(s1.verify(key1.publicKey, message2))
        assertFalse(s1.verify(key2.publicKey, message1))

        val s2 = Signature.from(key2, message2)
        assertTrue(s2.verify(key2.publicKey, message2))
        assertFalse(s2.verify(key1.publicKey, message2))
        assertFalse(s2.verify(key2.publicKey, message1))
    }
}
