package crypto.curve25519.example.mimblewimble

import kotlin.test.*
import crypto.curve25519.math.*
import crypto.curve25519.utils.*
import crypto.curve25519.example.pedersen.Commitment

class Mimblewimble {
    @Test fun createTransaction() {

        // Alice has some tokens hidden in commitments.
        // She holds a bunch of blinding keys to prove ownership.
        val (val1, val2) = Pair(123L, 456L)
        val bk1 = FieldElement.random(GF25519)
        val bk2 = FieldElement.random(GF25519)
        val cm1 = Commitment.fromValue(val1, bk1)
        val cm2 = Commitment.fromValue(val2, bk2)

        val amountToSend = 200L
        val amountToRetain = val1 + val2 - amountToSend

        // Alice generates a secret key for her output.
        val aliceOutBk = FieldElement.random(GF25519)
        val aliceOut = Commitment.fromValue(amountToRetain, aliceOutBk)
        // And her part of shared randomness.
        val aliceRnd = FieldElement.random(GF25519)

        val keySum = GF25519.addMod(bk1, bk2)

        val offer = Transaction.Offer(
            meta = "Transaction hash".toByteArray(),
            amount = amountToSend,
            inputs = listOf(cm1, cm2),
            change = aliceOut,
            keyExcess = (aliceOutBk - keySum) * G,
            rnd = aliceRnd * G)

        // Alice sends the transaction offer to Bob.

        // Bob generates a secret key for his output.
        val bobOutBk = FieldElement.random(GF25519)
        // And his part of shared randomness.
        val bobRnd = FieldElement.random(GF25519)

        val acceptance = Transaction.acceptOffer(
            offer,
            bobOutBk,
            bobRnd)

        // Acceptance is null if offer is not valid.
        assertFalse(acceptance == null)

        // Now Bob sends his acceptance to Alice.
        val tx = Transaction.finalize(
            offer,
            acceptance,
            keySum,
            aliceOutBk,
            aliceRnd
        )

        // Finalization fails if acceptance does not match offer.
        assertFalse(tx == null)

        assertTrue(tx.isValid())
    }
}
