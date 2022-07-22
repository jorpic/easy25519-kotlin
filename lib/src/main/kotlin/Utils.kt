package crypto.curve25519.utils

import java.security.MessageDigest
import java.util.Random
import crypto.curve25519.ModL



fun hash(vararg msg: ByteArray): ModL {
    val md = MessageDigest.getInstance("SHA-512")
    msg.forEach {
        md.update(it)
    }
    return ModL.from64Bytes(md.digest())
}

fun String.decodeHex(): ByteArray =
    this.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
