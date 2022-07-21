package crypto.curve25519

import java.util.Random
import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.math.FieldElement as _FieldElement
import net.i2p.crypto.eddsa.math.ScalarOps


// TODO[comment]: Coefficients of curve
open class FieldElement
    protected constructor (val el: _FieldElement) 
{
    companion object {
        fun fromBytesLE(b: ByteArray) = FieldElement(
            Curve.field.fromByteArray(b)
        )

        fun from64Bytes(b: ByteArray) = FieldElement(
            Curve.field.fromByteArray(
                Curve.scalarOps.reduce(b))
        )

        fun fromLong(x: Long) = FieldElement(
            Curve.field.fromByteArray(
                ByteArray(32).also {
                    for (i in 0..3) it[i] = (x shr (i*8)).toByte()
                }
            )
        )

        private val rnd = Random()

        fun random(): FieldElement = ByteArray(32).let {
            rnd.nextBytes(it)
            it[31] = (it[31].toInt() and 0x3f).toByte()
            FieldElement.fromBytesLE(it)
        }

        val ZERO = FieldElement.fromLong(0)
        val ONE = FieldElement.fromLong(1)

        // TODO: explain what is L
        // TODO[comment]: x*y + z (mod l)
        fun mulAddModL(x: FieldElement, y: FieldElement, z: FieldElement) =
            FieldElement(
                Curve.field.fromByteArray(
                    Curve.scalarOps.multiplyAndAdd(
                        x.toBytes(), y.toBytes(), z.toBytes()))
            )

        fun mulModL(x: FieldElement, y: FieldElement) =
            FieldElement.mulAddModL(x, y, FieldElement.ZERO)

        fun addModL(x: FieldElement, y: FieldElement) =
            FieldElement.mulAddModL(x, FieldElement.ONE, y)
    }

    // Arithmetic operations
    operator fun plus(x: FieldElement) = FieldElement(el.add(x.el))
    operator fun minus(x: FieldElement) = FieldElement(el.subtract(x.el))
    operator fun times(x: FieldElement) = FieldElement(el.multiply(x.el))
    operator fun div(x: FieldElement) = FieldElement(el.divide(x.el))

    // Structural equality
    override fun equals(other: Any?)
        = other is FieldElement && this.el.equals(other.el)

    override fun hashCode() = this.el.hashCode()

    // Utility
    fun toBytes() = this.el.toByteArray()
    fun toHex() = Utils.bytesToHex(this.toBytes())
}
