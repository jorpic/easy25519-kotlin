package crypto.curve25519

import java.util.Random
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

        fun random(): GroupElement {
            val b = ByteArray(32)
            val rnd = Random()
            while(true) {
                try {
                    rnd.nextBytes(b)
                    return GroupElement.fromBytes(b)
                } catch (e: IllegalArgumentException) {}
            }
        }
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

    fun checkPeriod(n: Long): Long {
        var p = this + this
        var i = n
        while(--i > 0 && p != this && p != Curve.basePoint) {
            p = p + this
        }
        return n - i
    }
}


operator fun FieldElement.times(x: GroupElement) = x * this
