package crypto.curve25519.example.mimblewimble

import kotlin.test.*
import crypto.curve25519.*
import crypto.curve25519.example.pedersen.Commitment

class Mimblewimble {

    // Token owner knows its value and blinding key.
    data class Token(
        val value: Long,
        val bk: FieldElement = FieldElement.random(),
        val cm: Commitment = Commitment.fromValue(value, bk),
    )

    @Test fun createTransaction() {
        // Alice has some tokens hidden in commitments.
        val inputs = listOf(Token(123), Token(234), Token(567))

        val amountToSend = 923L
        val amountToRetain = inputs.fold(-amountToSend, {x, y -> x + y.value})

        // Alice generates a secret key for her output.
        val aliceOutBk = FieldElement.random()
        val aliceOut = Commitment.fromValue(amountToRetain, aliceOutBk)
        // And her part of shared randomness.
        val aliceRnd = FieldElement.random()

        val privateExcess = ModL.sub(
            aliceOutBk,
            inputs.fold(ModL.ZERO, {x, y -> ModL.add(x, y.bk)}))

        val offer = Transaction.Offer(
            meta = "Transaction hash".toByteArray(),
            amount = amountToSend,
            inputs = inputs.map { it.cm },
            output = aliceOut,
            excess = privateExcess * G,
            rnd = aliceRnd * G)

        // Alice sends the transaction offer to Bob.

        // -------------------------------------------------------------------

        // Bob generates a key for his output (and stores it for further usage).
        val bobOutBk = FieldElement.random()
        val acceptance = Transaction.acceptOffer(offer, bobOutBk, rnd = FieldElement.random())

        // Acceptance is null if offer is not valid.
        assertTrue(acceptance != null)

        // Now Bob sends his acceptance to Alice.

        // -------------------------------------------------------------------

        // Alice finalizes the transaction and sends it back to Bob.
        val tx = Transaction.finalize(offer, acceptance, privateExcess, aliceRnd)

        // Finalization fails if acceptance does not match offer.
        assertTrue(tx != null)

        // -------------------------------------------------------------------

        // Anyone can check if transaction is valid.
        assertTrue(tx.isValid())
    }
}
