package dev.cluvex.zedsecure.di

import org.junit.Assert.*
import org.junit.Test
import java.util.UUID

class SubscriptionDeviceInfoTest {
    @Test fun stableIdentifierAndMissingId() {
        val value = subscriptionHwid("abc")!!
        assertEquals("ba7816bf-8f01-8fea-8141-40de5dae2223", value)
        assertEquals(value, subscriptionHwid("abc"))
        val uuid = UUID.fromString(value)
        assertEquals(value, uuid.toString())
        assertEquals(8, uuid.version())
        assertEquals(2, uuid.variant())
        assertNull(subscriptionHwid(""))
    }

    @Test fun disabledOrMissingIdOmitsDeviceHeaders() {
        assertTrue(subscriptionDeviceHeaders(false, "abc", "14", "Phone").isEmpty())
        assertTrue(subscriptionDeviceHeaders(true, "", "14", "Phone").isEmpty())
        assertEquals(mapOf("x-hwid" to subscriptionHwid("abc"), "x-device-os" to "Android", "x-ver-os" to "14", "x-device-model" to "Phone"), subscriptionDeviceHeaders(true, "abc", "14", "Phone"))
    }
}
