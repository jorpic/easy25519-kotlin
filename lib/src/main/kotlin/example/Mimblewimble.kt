package crypto.curve25519.example.mimblewimble

import crypto.curve25519.*
import crypto.curve25519.utils.*
import crypto.curve25519.example.pedersen.Commitment

val G = Curve.basePoint

typealias Commitments = List<Commitment>

data class Transaction(
    val inputs: Commitments,
    val outputs: Commitments,
    val signature: FieldElement,
    val rnd: GroupElement,
    val meta: ByteArray)
{
    fun isValid(): Boolean {
        val ex = kernelExcess(inputs, outputs)
        return signature * G == H(rnd, ex, meta) * ex + rnd
    }

    data class Offer(
        val amount: Long,
        val inputs: Commitments,
        val output: Commitment,
        val excess: GroupElement,
        val rnd: GroupElement,
        val meta: ByteArray,
    )

    data class Acceptance(
        val output: Commitment,
        val outBf: GroupElement,
        val sig: FieldElement,
        val rnd: GroupElement,
    )

    companion object {
        fun acceptOffer(
            offer: Offer,
            outBk: FieldElement,
            rnd: FieldElement
        ): Acceptance? {
            val accOut = Commitment.fromValue(offer.amount, outBk)
            val outBf = outBk * G
            val ex = kernelExcess(offer.inputs, listOf(offer.output, accOut))
            // Sender knows blinding keys and inputs - outputs = 0
            val isValidOffer = offer.excess + outBf == ex

            if (isValidOffer) {
                val R = rnd * G
                val h = H(offer.rnd + R, ex, offer.meta)
                return Acceptance(
                    accOut,
                    outBf,
                    sig = ModL.mulAdd(h, outBk, rnd),
                    R
                )
            } else return null
        }

        fun finalize(
            offer: Offer,
            acc: Acceptance,
            privateExcess: ModL,
            rnd: FieldElement
        ): Transaction? {
            val R = offer.rnd + acc.rnd
            val h = H(R, offer.excess + acc.outBf, offer.meta)
            // Receiver's signature is valid
            val isValidAcceptance = acc.sig * G == acc.outBf * h + acc.rnd

            if (isValidAcceptance) {
                return Transaction(
                    inputs = offer.inputs,
                    outputs = listOf(offer.output, acc.output), // FIXME: sort
                    signature = ModL.mulAdd(h, privateExcess, rnd) + acc.sig,
                    rnd = R,
                    meta = offer.meta
                )
            } else return null
        }

        // Helper functions

        // kernelExcess = outputs - inputs
        private fun kernelExcess(inputs: Commitments, outputs: Commitments) =
            inputs.fold(
                outputs.reduce { x, y -> x + y },
                { x, inp -> x - inp }
            ).ge

        private fun H(rnd: GroupElement, excess: GroupElement, meta: ByteArray) =
                hash(rnd.toBytes(), excess.toBytes(), meta)
    }
}
