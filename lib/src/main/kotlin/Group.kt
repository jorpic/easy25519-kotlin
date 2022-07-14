package crypto.curve25519.math.group

import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.math.GroupElement as _GroupElement
import crypto.curve25519.math.curve.Curve25519
import crypto.curve25519.math.field.*

class CurveGroup
    protected constructor(val el: _GroupElement)
{
    override fun equals(other: Any?)
        = other is CurveGroup && this.el.equals(other.el)

    override fun hashCode() = this.el.hashCode()

    // Utility
    fun toBytes() = this.el.toByteArray()
    fun toHex() = Utils.bytesToHex(this.toBytes())


    fun add(x: CurveGroup): Grp = CurveGroup(this.el.add(x.el))
    fun sub(x: CurveGroup): Grp = CurveGroup(this.el.sub(x.el))
    fun mul(x: GF25519ModL): Grp =
        CurveGroup(this.el.scalarMultiply(x.toBytes()))

    companion object {
        fun fromUntyped(el: _GroupElement) = CurveGroup(el)

        fun doubleMul(
            x: GF25519ModL, a: CurveGroup,
            y: GF25519ModL, b: CurveGroup
        ) = CurveGroup(
           b.el.doubleScalarMultiplyVariableTime(a.el, x.toBytes(), y.toBytes())
        )

    }

}

private typealias Grp = CurveGroup
private typealias GrE = CurveGroup_Expr
private typealias GF = GF25519
private typealias GFL = GF25519ModL
private typealias GFE = GF25519ModL_Expr


sealed abstract class CurveGroup_Expr {
    abstract fun eval(): Grp
    override fun equals(other: Any?) =
        other is CurveGroup_Expr && this.eval() == other.eval()
    override fun hashCode() = this.eval().hashCode()
}

private data class Val(val v: Grp): GrE() {
    override fun eval() = v
}

private data class Add(val x: GrE, val y: GrE): GrE() {
    override fun eval() = Add.eval(x, y)

    companion object {
        fun eval(x: GrE, y: GrE): Grp = when (x) {
            is Val -> when (y) {
                is Mul -> Add.eval(y, x)
                else -> x.eval().add(y.eval())
            }
            is Add -> when (y) {
                is Mul -> Add.eval(y, x)
                else -> x.eval().add(y.eval())
            }
            is Mul -> when (y) {
                is Mul -> CurveGroup.doubleMul(x.x, x.y.eval(), y.x, y.y.eval())
                else -> CurveGroup.doubleMul(
                    x.x, x.y.eval(),
                    GF25519ModL.ONE, y.eval())
            }
        }
    }
}

private data class Mul(val x: GFL, val y: GrE): GrE() {
    override fun eval(): Grp = when (y) {
        is Val -> y.eval().mul(x)
        is Add -> CurveGroup.doubleMul(x, y.x.eval(), x, y.y.eval())
        is Mul -> Mul((x * y.x).eval(), y.y).eval()
    }
}


operator fun GF.times(x: Grp): GrE = Mul(
    GF25519ModL.fromUnsafeUntyped(this.el),
    Val(x))
operator fun GFE.times(x: Grp): GrE = Mul(this.eval(), Val(x))
operator fun GF.times(x: GrE): GrE = Mul(
    GF25519ModL.fromUnsafeUntyped(this.el),
    x)
operator fun GFE.times(x: GrE): GrE = Mul(this.eval(), x)

operator fun Grp.plus(x: Grp): GrE = Add(Val(this), Val(x))
operator fun Grp.plus(x: GrE): GrE = Add(Val(this), x)
operator fun GrE.plus(x: Grp): GrE = Add(this, Val(x))
operator fun GrE.plus(x: GrE): GrE = Add(this, x)
// operator fun Grp.minus(x: Grp): GrE = 
