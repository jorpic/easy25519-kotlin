package crypto.curve25519

import java.util.Random
import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.math.FieldElement as _FieldElement
import net.i2p.crypto.eddsa.math.ScalarOps
import crypto.curve25519.utils.decodeHex


// TODO[comment]: Coefficients of curve
open class FieldElement
    protected constructor (val el: _FieldElement) 
{
    companion object {
        fun fromBytesLE(b: ByteArray) = FieldElement(
            Curve.field.fromByteArray(b)
        )

        private val rnd = Random()

        fun random(): FieldElement = ByteArray(32).let {
            rnd.nextBytes(it)
            it[31] = (it[31].toInt() and 0x3f).toByte()
            FieldElement.fromBytesLE(it)
        }
    }

    // Arithmetic operations
    operator fun plus(x: FieldElement) = FieldElement(el.add(x.el))
    operator fun minus(x: FieldElement) = FieldElement(el.subtract(x.el))
    operator fun times(x: FieldElement) = FieldElement(el.multiply(x.el))
    operator fun div(x: FieldElement) = FieldElement(el.divide(x.el))
    operator fun unaryMinus() = FieldElement(el.negate())

    // Structural equality
    override fun equals(other: Any?)
        = other is FieldElement && this.el.equals(other.el)

    override fun hashCode() = this.el.hashCode()

    // Utility
    fun toBytes() = this.el.toByteArray()
    fun toHex() = Utils.bytesToHex(this.toBytes())
}


// TODO: explain what is L
class ModL(el: _FieldElement) : FieldElement(el) {
    constructor(fe: FieldElement) : this(ModL.add(fe, ModL.ZERO).el)

    companion object {
        fun from64Bytes(b: ByteArray) = ModL(
            Curve.field.fromByteArray(
                Curve.scalarOps.reduce(b))
        )

        fun fromLong(x: Long) = ModL(
            Curve.field.fromByteArray(
                ByteArray(32).also {
                    for (i in 0..3) it[i] = (x shr (i*8)).toByte()
                }
            )
        )

        // 2^{252} + 27742317777372353535851937790883648493
        val L = FieldElement.fromBytesLE(
            "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
            .decodeHex()
        )
        val ZERO = ModL.fromLong(0)
        val ONE = ModL.fromLong(1)

        // Operations
        // TODO[comment]: x*y + z (mod l)
        fun mulAdd(x: FieldElement, y: FieldElement, z: FieldElement) =
            ModL(
                Curve.field.fromByteArray(
                    Curve.scalarOps.multiplyAndAdd(
                        x.toBytes(), y.toBytes(), z.toBytes()))
            )

        fun mul(x: FieldElement, y: FieldElement) = ModL.mulAdd(x, y, ModL.ZERO)
        fun add(x: FieldElement, y: FieldElement) = ModL.mulAdd(x, ModL.ONE, y)
        fun negate(x: ModL) = ModL((ModL.L - x).el)
        fun sub(x: FieldElement, y: ModL) =
            ModL.mulAdd(x, ModL.ONE, ModL.negate(y))
    }
}
