package org.clipbridge.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.clipbridge.android.core.AndroidIdentityStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidIdentityStoreInstrumentedTest {
    @Test fun protectedIdentityPersistsAndCorruptionFailsClosed() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val store = AndroidIdentityStore(context)
        val first = store.loadOrCreate()
        val second = AndroidIdentityStore(context).loadOrCreate()
        assertEquals(first.deviceId, second.deviceId)

        val ciphertext = context.noBackupFilesDir.resolve("identity.v1.ciphertext")
        val bytes = ciphertext.readBytes()
        assertEquals(136, bytes.size)
        assertFalse(bytes.copyOfRange(0, 4).contentEquals(byteArrayOf(67, 66, 73, 68)))
        bytes[30] = (bytes[30].toInt() xor 0x40).toByte()
        ciphertext.writeBytes(bytes)
        assertThrows(Exception::class.java) {
            AndroidIdentityStore(context).loadOrCreate()
        }
    }
}
