package io.juist.app

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import io.juist.app.core.QrDecoder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class QrDecoderTest {
    private val link = "juist:WZC5a3azNL5k2uiLrNy9Cw.cozlyxz0l-e4V2ociDnxP6zVUJVDox49Rs9pKxdIA_I@192.0.2.1:41642,[2001:db8::1]:41642"

    /** A frame of 640 by 480 with link's code drawn in it, each row padded as a camera's are. */
    private fun frame(dark: Byte, light: Byte, padding: Int = 64): Triple<ByteArray, Int, Pair<Int, Int>> {
        val (w, h) = 640 to 480
        val stride = w + padding
        val m = QRCodeWriter().encode(link, BarcodeFormat.QR_CODE, 360, 360, mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L))
        val bytes = ByteArray(stride * h) { light }
        for (y in 0 until m.height) for (x in 0 until m.width) {
            if (m[x, y]) bytes[(y + 60) * stride + x + 140] = dark
        }
        return Triple(bytes, stride, w to h)
    }

    @Test
    fun readsACodeDarkOnLight() {
        val (bytes, stride, size) = frame(dark = 20, light = -36)
        assertEquals(link, QrDecoder().decode(bytes, stride, size.first, size.second))
    }

    @Test
    fun readsACodeLightOnDark() {
        val (bytes, stride, size) = frame(dark = -36, light = 20)
        assertEquals(link, QrDecoder().decode(bytes, stride, size.first, size.second))
    }

    @Test
    fun findsNothingInAnEmptyFrame() {
        assertNull(QrDecoder().decode(ByteArray(640 * 480) { 90 }, 640, 640, 480))
    }
}
