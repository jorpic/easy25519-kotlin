package crypto.curve25519.math.curve

import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import crypto.curve25519.math.group.*

object Curve25519 {
    val spec = EdDSANamedCurveTable.ED_25519_CURVE_SPEC
    val basePoint = CurveGroup.fromUntyped(spec.getB())
}
