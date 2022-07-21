package crypto.curve25519

import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable

object Curve {
    val spec = EdDSANamedCurveTable.ED_25519_CURVE_SPEC
    val field = this.spec.curve.field
    val scalarOps = this.spec.getScalarOps()
    val basePoint = GroupElement.fromUntyped(this.spec.getB())
}
