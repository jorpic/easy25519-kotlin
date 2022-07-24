package crypto.curve25519

import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.math.GroupElement as _GroupElement
import crypto.curve25519.Curve
import crypto.curve25519.FieldElement


class GroupElement
    private constructor(val el: _GroupElement)
{
    companion object {
        // Returns GroupElement in P3PrecomputedDouble representation.
        fun fromBytes(b: ByteArray) = GroupElement(
            _GroupElement(Curve.spec.curve, b, true)
        )

        fun fromUntyped(el: _GroupElement) = GroupElement(el)
    }

    // Representation conversions
    // FIXME: there could be a better way to get P3 with precomputed single
    fun toP3() = GroupElement.fromBytes(this.toBytes())
    fun toCached() = GroupElement(this.toP3().el.toCached())


    // Arithmetics
    operator fun plus(x: GroupElement) = GroupElement(
        this.toP3().el.add(x.toCached().el)
    )

    operator fun minus(x: GroupElement) = GroupElement(
        this.toP3().el.sub(x.toCached().el)
    )

    operator fun times(x: FieldElement) = GroupElement(
        this.toP3().el.scalarMultiply(x.toBytes())
    )

    // Equality
    override fun equals(other: Any?)
        = other is GroupElement && this.toHex() == other.toHex()
    override fun hashCode() = this.el.hashCode()

    // Utility
    fun toBytes() = this.el.toByteArray()
    fun toHex() = Utils.bytesToHex(this.toBytes())
}


operator fun FieldElement.times(x: GroupElement) = x * this
