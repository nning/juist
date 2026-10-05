package io.juist.app.ui.screens

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import android.util.Size
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalIconToggleButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size as GSize
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import io.juist.app.R
import io.juist.app.core.InviteCode
import io.juist.app.core.QrDecoder
import io.juist.app.ui.components.BackBar
import io.juist.app.ui.components.IconBadge
import io.juist.app.ui.components.Readable
import io.juist.app.ui.theme.Space
import java.util.concurrent.Executors
import androidx.lifecycle.compose.LifecycleResumeEffect
import kotlinx.coroutines.delay

/** The camera, looking for the QR code `juist invite` draws, with the permission asked for first. */
@Composable
fun ScanRoute(onInvite: (String) -> Unit, onCode: () -> Unit, onBack: () -> Unit) {
    val context = LocalContext.current
    fun allowed() = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
    var granted by remember { mutableStateOf(allowed()) }
    // Back from the app's settings, where it may have been allowed.
    LifecycleResumeEffect(Unit) {
        granted = allowed()
        onPauseOrDispose {}
    }
    var asked by rememberSaveable { mutableStateOf(false) }
    val request = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        granted = it
        asked = true
    }
    ScanScreen(
        granted = granted,
        denied = asked && !granted,
        onAllow = {
            if (asked) {
                context.startActivity(
                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null)),
                )
            } else {
                request.launch(Manifest.permission.CAMERA)
            }
        },
        onInvite = onInvite,
        onCode = onCode,
        onBack = onBack,
    ) { torch, found -> CameraPreview(torch, found) }
}

@Composable
fun ScanScreen(
    granted: Boolean,
    denied: Boolean,
    onAllow: () -> Unit,
    onInvite: (String) -> Unit,
    onCode: () -> Unit,
    onBack: () -> Unit,
    camera: @Composable (torch: Boolean, found: (String) -> Unit) -> Unit,
) {
    var torch by rememberSaveable { mutableStateOf(false) }
    var notAnInvite by remember { mutableStateOf(false) }
    var found by remember { mutableStateOf(false) }
    val haptics = LocalHapticFeedback.current
    LaunchedEffect(notAnInvite) {
        if (notAnInvite) {
            delay(2500)
            notAnInvite = false
        }
    }
    Scaffold(topBar = { BackBar(stringResource(R.string.scan_title), onBack) }) { padding ->
        if (!granted) {
            CameraAsk(denied, onAllow, onCode, Modifier.padding(padding))
            return@Scaffold
        }
        Box(Modifier.padding(padding).fillMaxSize()) {
            camera(torch) { text ->
                if (found) return@camera
                if (InviteCode.isLink(text)) {
                    found = true
                    haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                    onInvite(text.trim())
                } else {
                    notAnInvite = true
                }
            }
            Viewfinder(Modifier.fillMaxSize())
            Column(
                Modifier.align(Alignment.BottomCenter).fillMaxWidth().padding(Space.xl),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(Space.m),
            ) {
                Surface(shape = MaterialTheme.shapes.medium, color = Color.Black.copy(alpha = 0.6f)) {
                    Text(
                        stringResource(if (notAnInvite) R.string.scan_not_invite else R.string.scan_hint),
                        Modifier.padding(horizontal = Space.l, vertical = Space.m),
                        color = Color.White,
                        style = MaterialTheme.typography.bodyMedium,
                        textAlign = TextAlign.Center,
                    )
                }
                FilledTonalIconToggleButton(torch, { torch = it }, Modifier.size(56.dp)) {
                    Icon(painterResource(R.drawable.ic_flash), stringResource(R.string.scan_torch))
                }
            }
        }
    }
}

@Composable
private fun CameraAsk(denied: Boolean, onAllow: () -> Unit, onCode: () -> Unit, modifier: Modifier) {
    Readable(modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        Column(Modifier.padding(Space.xl), horizontalAlignment = Alignment.CenterHorizontally) {
            Spacer(Modifier.height(Space.xxl))
            IconBadge(
                painterResource(R.drawable.ic_qr), MaterialTheme.colorScheme.onPrimaryContainer,
                MaterialTheme.colorScheme.primaryContainer,
            )
            Spacer(Modifier.height(Space.xl))
            Text(
                stringResource(R.string.scan_camera_title),
                style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(Space.m))
            Text(
                stringResource(if (denied) R.string.scan_camera_denied else R.string.scan_camera_body),
                style = MaterialTheme.typography.bodyLarge, textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(Space.xl))
            Button(onAllow, Modifier.fillMaxWidth()) {
                Text(stringResource(if (denied) R.string.action_open_settings else R.string.action_allow_camera))
            }
            Spacer(Modifier.height(Space.m))
            OutlinedButton(onCode, Modifier.fillMaxWidth()) { Text(stringResource(R.string.action_enter_code)) }
        }
    }
}

/** A clear rounded square in a dimmed frame, its corners in the accent. */
@Composable
private fun Viewfinder(modifier: Modifier) {
    val accent = MaterialTheme.colorScheme.primary
    Box(modifier) {
        Canvas(Modifier.fillMaxSize().graphicsLayer(compositingStrategy = CompositingStrategy.Offscreen)) {
            val side = size.minDimension * 0.72f
            val topLeft = Offset((size.width - side) / 2, (size.height - side) / 2.6f)
            val radius = CornerRadius(28.dp.toPx())
            drawRect(Color.Black.copy(alpha = 0.55f))
            drawRoundRect(Color.Transparent, topLeft, GSize(side, side), radius, blendMode = BlendMode.Clear)
            drawRoundRect(accent, topLeft, GSize(side, side), radius, style = Stroke(4.dp.toPx()))
        }
    }
}

@Composable
private fun CameraPreview(torch: Boolean, found: (String) -> Unit) {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    var camera by remember { mutableStateOf<Camera?>(null) }
    val reader = remember { QrReader() }
    val view = remember { PreviewView(context).apply { scaleType = PreviewView.ScaleType.FILL_CENTER } }
    LaunchedEffect(torch, camera) { camera?.cameraControl?.enableTorch(torch) }
    DisposableEffect(owner) {
        val executor = Executors.newSingleThreadExecutor()
        val future = ProcessCameraProvider.getInstance(context)
        var disposed = false
        future.addListener({
            // The screen may have gone before the camera was ready.
            if (disposed) return@addListener
            val provider = future.get()
            val preview = Preview.Builder().build().also { it.surfaceProvider = view.surfaceProvider }
            val analysis = ImageAnalysis.Builder()
                .setResolutionSelector(
                    ResolutionSelector.Builder().setResolutionStrategy(
                        ResolutionStrategy(Size(1280, 720), ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER),
                    ).build(),
                )
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            analysis.setAnalyzer(executor) { image ->
                val text = image.use { reader.read(it) }
                if (text != null) ContextCompat.getMainExecutor(context).execute { found(text) }
            }
            provider.unbindAll()
            camera = provider.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
        }, ContextCompat.getMainExecutor(context))
        onDispose {
            disposed = true
            if (future.isDone) runCatching { future.get().unbindAll() }
            executor.shutdown()
        }
    }
    AndroidView({ view }, Modifier.fillMaxSize())
}

/** Reads a QR code from a camera frame's luminance, the Y plane. */
private class QrReader {
    private val decoder = QrDecoder()
    private var bytes = ByteArray(0)

    fun read(image: ImageProxy): String? {
        val plane = image.planes[0]
        val size = plane.buffer.remaining()
        if (bytes.size != size) bytes = ByteArray(size)
        plane.buffer.get(bytes)
        return decoder.decode(bytes, plane.rowStride, image.width, image.height)
    }
}
