package io.juist.app.core

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

/**
 * Finds a QR code in a frame's luminance, dark on light or, as `juist invite`
 * draws it on a light terminal without colours, light on dark.
 */
class QrDecoder {
    private val reader = QRCodeReader()
    private val hints = mapOf(
        DecodeHintType.TRY_HARDER to true,
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
    )

    /** The code's text, or null; rows are rowStride bytes apart, of which width are the image's. */
    fun decode(luminance: ByteArray, rowStride: Int, width: Int, height: Int): String? {
        val source = PlanarYUVLuminanceSource(luminance, rowStride, height, 0, 0, width, height, false)
        for (s in listOf(source, source.invert())) {
            try {
                return reader.decode(BinaryBitmap(HybridBinarizer(s)), hints).text
            } catch (_: ReaderException) {
            } catch (_: RuntimeException) {
                // zxing's on a frame it misreads; thrown on the analyzer's thread, it would end the app.
            } finally {
                reader.reset()
            }
        }
        return null
    }
}
