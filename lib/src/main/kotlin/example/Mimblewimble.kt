package crypto.curve25519.example.mimblewimble

import crypto.curve25519.math.*
import crypto.curve25519.utils.*
import crypto.curve25519.example.pedersen.Commitment



data class Transaction(
    val inputs: List<Commitment>,
    val outputs: List<Commitment>,
    val signature: FieldElement<GF25519>,
    val rnd: GroupElement<Curve25519, Rep.U>,
    val meta: ByteArray)
{
    fun isValid(): Boolean {
        val kernelExcess = inputs.fold(
            outputs.reduce { x, y -> x + y },
            { x, y -> x - y }).ge
        val h = hash(this.rnd.toBytes(), kernelExcess.toBytes(), this.meta)
        return this.signature * G == h * kernelExcess
    }

    data class Offer(
        val amount: Long,
        val inputs: List<Commitment>,
        val change: Commitment,
        val keyExcess: GroupElement<Curve25519, Rep.U>,
        val rnd: GroupElement<Curve25519, Rep.U>,
        val meta: ByteArray,
    )

    data class Acceptance(
        val output: Commitment,
        val blindingFactor: GroupElement<Curve25519, Rep.U>,
        val sig: FieldElement<GF25519>,
        val rnd: GroupElement<Curve25519, Rep.U>
    )

    companion object {
        fun acceptOffer(
            offer: Offer,
            outputBlindingKey: FieldElement<GF25519>,
            rnd: FieldElement<GF25519>
        ): Acceptance? {
            val output = Commitment.fromValue(offer.amount, outputBlindingKey)
            val blindingFactor = outputBlindingKey * G

            val kernelExcess = offer.inputs.fold(
                offer.change + output,
                { x, inp -> x - inp }
            ).ge

            val isValidOffer =
                offer.keyExcess + blindingFactor == kernelExcess

            if (isValidOffer) {
                val h = hash(
                    (offer.rnd + rnd * G).toBytes(),
                    (offer.keyExcess + blindingFactor).toBytes(),
                    offer.meta)

                return Acceptance(
                    output,
                    outputBlindingKey * G,
                    GF25519.mulAddMod(h, outputBlindingKey, rnd),
                    rnd * G
                )
            } else return null
        }


        fun finalize(
            offer: Offer,
            acc: Acceptance,
            inputKeySum: FieldElement<GF25519>,
            outputBlindingKey: FieldElement<GF25519>,
            rnd: FieldElement<GF25519>
        ): Transaction? {
            val h = hash(
                (offer.rnd + acc.rnd).toBytes(),
                (offer.keyExcess + acc.blindingFactor).toBytes(),
                offer.meta)

            val isValidAcceptance =
                acc.sig * G == acc.blindingFactor * h + acc.rnd

            if (isValidAcceptance) {
                val bk = outputBlindingKey - inputKeySum
                return Transaction(
                    inputs = offer.inputs,
                    outputs = listOf(offer.change, acc.output),
                    signature = acc.sig + GF25519.mulAddMod(h, bk, rnd),
                    rnd = acc.rnd + rnd * G,
                    meta = offer.meta
                )
            } else return null
        }
    }
}
