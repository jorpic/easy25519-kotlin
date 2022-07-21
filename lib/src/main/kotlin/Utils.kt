package crypto.curve25519.utils

import java.security.MessageDigest
import java.util.Random
import crypto.curve25519.FieldElement



fun hash(vararg msg: ByteArray): FieldElement {
    val md = MessageDigest.getInstance("SHA-512")
    msg.forEach {
        md.update(it)
    }
    return FieldElement.from64Bytes(md.digest())
}
