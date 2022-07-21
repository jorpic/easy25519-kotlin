package crypto.curve25519.math.field

import java.util.Random
import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.math.FieldElement as _FieldElement
import crypto.curve25519.math.curve.Curve25519


private val rnd = Random()

open class GF25519
    protected constructor(val el: _FieldElement)
{

    companion object {
        val field = Curve25519.spec.curve.field

        fun fromBytesLE(b: ByteArray) = GF25519(GF25519.field.fromByteArray(b))

        fun fromLong(x: Long) = GF25519ModL.fromLong(x)

        fun random() = ByteArray(32).let {
            rnd.nextBytes(it)
            it[31] = (it[31].toInt() and 0x3f).toByte()
            GF25519.fromBytesLE(it)
        }
    }

    fun reduce(): GF25519ModL = GF25519ModL.add(GF25519ModL.ZERO, this)

    override fun equals(other: Any?)
        = other is GF25519 && this.el.equals(other.el)

    override fun hashCode() = this.el.hashCode()

    // Utility
    fun toBytes() = this.el.toByteArray()
    fun toHex() = Utils.bytesToHex(this.toBytes())
}



class GF25519ModL: GF25519
{
    protected constructor(el: _FieldElement) : super(el)

    companion object {
        val scalarOps = Curve25519.spec.getScalarOps()
        val ZERO = GF25519ModL.fromLong(0)
        val ONE = GF25519ModL.fromLong(1)

        fun mul(x: GF, y: GF) = mulAdd(x, y, ZERO)
        fun add(x: GF, y: GF) = mulAdd(x, ONE, y)
        fun mulAdd(x: GF, y: GF, z: GF) = GFL.fromBytesLE(
            GFL.scalarOps.multiplyAndAdd(
                x.toBytes(), y.toBytes(), z.toBytes())
        )

        // For Curve25519.basePoint L is greater than 2^240 so we can safely
        // assume that Long belongs to GF25519ModL
        fun fromLong(x: Long) = GF25519ModL(
            GF25519.field.fromByteArray(
                ByteArray(32).also {
                    for (i in 0..3) it[i] = (x shr (i*8)).toByte()
                }
            )
        )

        fun fromBytesLE(b: ByteArray) =
            GF25519ModL(GF25519.field.fromByteArray(b))

        fun fromBytes64(b: ByteArray) =
            GF25519ModL.fromBytesLE(scalarOps.reduce(b))

        fun fromUnsafeUntyped(el: _FieldElement) = GF25519ModL(el)
    }
}

private typealias GF = GF25519
private typealias GFL = GF25519ModL
private typealias GFE = GF25519ModL_Expr


interface Ops {
    fun mul(x: GF, y: GF): GFL
    fun add(x: GF, y: GF): GFL
    fun mulAdd(x: GF, y: GF, z: GF): GFL
}

private class ScalarOps: Ops {
    override fun mul(x: GF, y: GF) = GF25519ModL.mul(x, y)
    override fun add(x: GF, y: GF) = GF25519ModL.add(x, y)
    override fun mulAdd(x: GF, y: GF, z: GF) = GF25519ModL.mulAdd(x, y, z)
}


sealed class GF25519ModL_Expr {
    abstract fun eval(): GFL
    abstract fun trace(): String

    override fun equals(other: Any?) = when (other) {
        is GF25519ModL_Expr -> this.eval().equals(other.eval())
        is GF25519 -> this.eval().equals(other)
        else -> false
    }

    override fun hashCode() = this.eval().hashCode()

    companion object {
        val scalarOps: Ops = ScalarOps()
    }
}

data class Val(val v: GF) : GFE() {
    // NB: we hope that Val.eval() will be called only as a part of complex
    // expression, and most of the cases will be transformed into
    // mul/add/mulAdd or group scalar multiplication.
    override fun eval() = GF25519ModL.fromUnsafeUntyped(v.el)
    override fun trace() = "Val(${v.toHex()})"
}

private data class Add(val x: GFE, val y: GFE) : GFE() {
    override fun eval() = Add.eval(GF25519ModL_Expr.scalarOps, x, y)
    override fun trace() = ""

    companion object {
        fun eval(op: Ops, x: GFE, y: GFE): GFL = when (x) {
            is Val -> when (y) { // x + ...
                is Mul -> op.mulAdd(y.x.eval(), y.y.eval(), x.v)
                else -> op.add(x.eval(), y.eval())
            }
            is Add -> when (y) { // (x + y) + ...
                is Mul -> op.mulAdd(y.x.eval(), y.y.eval(), x.eval())
                else -> op.add(x.eval(), y.eval())
            }
            is Mul -> // (x * y) + ...
                op.mulAdd(x.x.eval(), x.y.eval(), y.eval())
        }
    }
}

private data class Mul(val x: GFE, val y: GFE) : GFE() {
    override fun eval() = Mul.eval(GF25519ModL_Expr.scalarOps, x, y)
    override fun trace() = ""

    companion object {
        fun eval(op: Ops, x: GFE, y: GFE): GFL = when (x) {
            is Val -> when (y) {
                // v * (x + y) = mulAdd(v, x, v*y)
                is Add -> op.mulAdd(
                    x.v, y.x.eval(), op.mul(x.v, y.y.eval()))
                else -> op.mul(x.eval(), y.eval())
            }
            is Add -> Mul.eval(op, Val(y.eval()), x)
            is Mul -> Mul.eval(op, Val(x.eval()), y)
        }
    }
}


// The goal here is to build expression tree which can be efficiently evaluated later.
operator fun GF.times(x: GF): GFE = Mul(Val(this), Val(x))
operator fun GF.times(x: GFE): GFE = Mul(Val(this), x)
operator fun GFE.times(x: GF): GFE = Mul(this, Val(x))
operator fun GFE.times(x: GFE): GFE = Mul(this, x)

operator fun GF.plus(x: GF): GFE = Add(Val(this), Val(x))
operator fun GF.plus(x: GFE): GFE = Add(Val(this), x)
operator fun GFE.plus(x: GF): GFE = Add(this, Val(x))
operator fun GFE.plus(x: GFE): GFE = Add(this, x)

// TODO: minus, unaryMinus
