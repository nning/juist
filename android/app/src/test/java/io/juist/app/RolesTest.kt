package io.juist.app

import io.juist.app.ui.screens.offeredRoles
import org.junit.Assert.assertEquals
import org.junit.Test

/** A phone is offered voucher alone, and only beside a computer; a computer every role. */
class RolesTest {
    @Test fun aPhoneIsOfferedVoucherBesideAComputerAlone() {
        assertEquals(listOf("relay", "voucher", "exit"), offeredRoles(phone = false, mixed = false, held = emptySet()))
        assertEquals(listOf("voucher"), offeredRoles(phone = true, mixed = true, held = emptySet()))
        assertEquals(emptyList<String>(), offeredRoles(phone = true, mixed = false, held = emptySet()))
        // One it holds stays, to be taken.
        assertEquals(listOf("relay", "voucher"), offeredRoles(phone = true, mixed = false, held = setOf("relay", "voucher")))
    }
}
