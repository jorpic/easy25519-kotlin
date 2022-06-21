package crypto.math.curve25519

import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.math.Field as _Field
import net.i2p.crypto.eddsa.math.FieldElement as _FieldElement
import net.i2p.crypto.eddsa.math.GroupElement as _GroupElement
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding
import java.util.Random
import java.security.MessageDigest


// Don't mix field elements from different fields


interface Field {
    val untypedField: _Field
}

class FieldElement<out F: Field>
    private constructor(val x: _FieldElement)
{
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
    }
}

interface Curve<out F: Field> {
    val spec: EdDSANamedCurveSpec
    val basePoint: GroupElement<Curve<F>>
}

class GroupElement<out C: Curve<*>>
    private constructor(val x: _GroupElement)
{
    companion object {
        fun <C: Curve<*>> P3(c: C, b: ByteArray)
            = GroupElement<C>(
                _GroupElement(c.spec.curve, b, true)
            )

        fun <C: Curve<*>> basePointOf(c: C)
            = GroupElement<C>(c.spec.getB())
    }
}



object GF25519 : Field {
    override val untypedField = Curve25519.spec.curve.field
}


object Curve25519: Curve<GF25519> {
    override val spec = EdDSANamedCurveTable.ED_25519_CURVE_SPEC
    override val basePoint = GroupElement.basePointOf<Curve25519>(this)
}
