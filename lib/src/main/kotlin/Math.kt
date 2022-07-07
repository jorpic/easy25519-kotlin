package crypto.curve25519.math

import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.math.Field as _Field
import net.i2p.crypto.eddsa.math.FieldElement as _FieldElement
import net.i2p.crypto.eddsa.math.GroupElement as _GroupElement
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding
import java.util.Random
import java.security.MessageDigest


interface Field {
    val untypedField: _Field
}


class FieldElement<F: Field>
    private constructor(val el: _FieldElement)
{
    // Constructors
    companion object {
        fun <F: Field> fromBytesLE(f: F, b: ByteArray) = FieldElement<F>(
            f.untypedField.fromByteArray(b)
        )

        fun <F: Field> fromLong(f: F, x: Long) = FieldElement.fromBytesLE<F>(
            f,
            ByteArray(32).also {
                for (i in 0..3) it[i] = (x shr (i*8)).toByte()
            }
        )

        fun <F: Field> fromUntyped(x: _FieldElement) = FieldElement<F>(x)
    }

    // Operators
    operator fun plus(x: FieldElement<F>) = FieldElement<F>(this.el.add(x.el))
    operator fun minus(x: FieldElement<F>) = FieldElement<F>(this.el.subtract(x.el))
    operator fun times(x: FieldElement<F>) = FieldElement<F>(this.el.multiply(x.el))
    operator fun div(x: FieldElement<F>) = FieldElement<F>(this.el.divide(x.el))

    // Structural equality
    override fun equals(other: Any?)
        = other is FieldElement<*>
        // FIXME: We can't check field tag here.
        // This allows elements from different fields to be considered equal.
        && this.el.equals(other.el)

    override fun hashCode() = this.el.hashCode()

    // Utility
    fun toBytes() = this.el.toByteArray()
    fun toHex() = Utils.bytesToHex(this.toBytes())
}

interface Curve<out F: Field> {
    val spec: EdDSANamedCurveSpec
}


class GroupElement<out C: Curve<*>, out R: GroupElement.Rep>
    private constructor(val x: _GroupElement)
{
    interface Rep
    class P1P1 : Rep
    class P2 : Rep
    class P3 : Rep // it is P3PrecomputedDouble actually


    companion object {
        fun <C: Curve<*>> P3(c: C, b: ByteArray)
            = GroupElement<C, P3>(
                _GroupElement(c.spec.curve, b, true)
            )

        fun <C: Curve<*>> basePointOf(c: C)
            = GroupElement<C, P3>(c.spec.getB())
    }
}


object GF25519 : Field {
    override val untypedField = Curve25519.spec.curve.field
}


object Curve25519: Curve<GF25519> {
    override val spec = EdDSANamedCurveTable.ED_25519_CURVE_SPEC
    val basePoint = GroupElement.basePointOf<Curve25519>(this)
}
