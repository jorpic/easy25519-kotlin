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


// GroupElement representation type tags
interface Rep {
    class P1P1 : Rep
    class P3 : Rep // it is P3PrecomputedDouble actually
    class CACHED : Rep
}

class GroupElement<C: Curve<*>, R: Rep>
    private constructor(val el: _GroupElement)
{
    // Constructors
    companion object {
        fun <C: Curve<*>> P3(c: C, b: ByteArray)
            = GroupElement<C, Rep.P3>(
                _GroupElement(c.spec.curve, b, true)
            )

        fun <C: Curve<*>> basePointOf(c: C)
            = GroupElement<C, Rep.P3>(c.spec.getB())

        fun <C: Curve<*>, R: Rep> fromUntyped(el: _GroupElement)
            = GroupElement<C, R>(el)
    }

    // Structural equality
    override fun equals(other: Any?)
        = other is GroupElement<*, *>
        // This allows elements from different fields to be considered equal.
        && this.el.equals(other.el)

    override fun hashCode() = this.el.hashCode()

    // Utility
    fun toBytes() = this.el.toByteArray()
    fun toHex() = Utils.bytesToHex(this.toBytes())
}


// Allowed representation conversions
fun <C: Curve<*>> // P3 -> CACHED
    GroupElement<C, Rep.P3>.toCached()
        = GroupElement.fromUntyped<C, Rep.CACHED>(this.el.toCached())

fun <C: Curve<*>> // P1P1 -> P3
    GroupElement<C, Rep.P1P1>.toP3()
        = GroupElement.fromUntyped<C, Rep.P3>(
            this.el.toP3PrecomputeDouble()
        )

// NB. Operators can't be part of class definition as we overload them
// depending on a generic parameter (representation tag).
operator fun <C: Curve<*>>
    GroupElement<C, Rep.P3>.plus(
        x: GroupElement<C, Rep.CACHED>
    ) = GroupElement.fromUntyped<C, Rep.P1P1>(this.el.add(x.el))

operator fun <C: Curve<*>>
    GroupElement<C, Rep.P3>.minus(
        x: GroupElement<C, Rep.CACHED>
    ) = GroupElement.fromUntyped<C, Rep.P1P1>(this.el.sub(x.el))

operator fun <F: Field, C: Curve<F>>
    GroupElement<C, *>.times(x: FieldElement<F>)
        = GroupElement.fromUntyped<C, Rep.P3>(
            this.el.scalarMultiply(x.toBytes())
        )

operator fun <F: Field, C: Curve<F>>
    FieldElement<F>.times(x: GroupElement<C, *>)
        = GroupElement.fromUntyped<C, Rep.P3>(
            x.el.scalarMultiply(this.toBytes())
        )


// Concrete implementations of Field<> and Curve<>
object GF25519 : Field {
    override val untypedField = Curve25519.spec.curve.field
}


object Curve25519: Curve<GF25519> {
    override val spec = EdDSANamedCurveTable.ED_25519_CURVE_SPEC
    val basePoint = GroupElement.basePointOf<Curve25519>(this)
}
