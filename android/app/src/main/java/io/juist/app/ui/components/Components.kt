package io.juist.app.ui.components

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import android.content.ClipData
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import kotlinx.coroutines.launch
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.clickable
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.TextAutoSize
import androidx.compose.ui.unit.sp
import io.juist.app.R
import io.juist.app.ui.theme.MonoBody
import io.juist.app.ui.theme.Space

/** The wordmark, its glyphs in the text colour and its link in the accent, as on the website. */
@Composable
fun Wordmark(modifier: Modifier = Modifier, height: Dp = 40.dp) {
    val description = stringResource(R.string.app_name)
    Box(modifier.semantics { contentDescription = description }) {
        Image(
            painterResource(R.drawable.wordmark_glyphs), null,
            Modifier.size(height * 286f / 98f, height),
            colorFilter = ColorFilter.tint(MaterialTheme.colorScheme.onBackground),
        )
        Image(
            painterResource(R.drawable.wordmark_link), null,
            Modifier.size(height * 286f / 98f, height),
            colorFilter = ColorFilter.tint(MaterialTheme.colorScheme.primary),
        )
    }
}

/** A dot in a status colour; pulsing, it says something is under way. */
@Composable
fun StatusDot(color: Color, modifier: Modifier = Modifier, size: Dp = 10.dp, pulse: Boolean = false) {
    val alpha = if (pulse) {
        val t = rememberInfiniteTransition(label = "pulse")
        val a by t.animateFloat(1f, 0.35f, infiniteRepeatable(tween(900), RepeatMode.Reverse), label = "alpha")
        a
    } else {
        1f
    }
    Box(modifier.size(size).clip(CircleShape).background(color.copy(alpha = alpha)))
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackBar(title: String, onBack: () -> Unit, actions: @Composable () -> Unit = {}) {
    TopAppBar(
        title = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        navigationIcon = {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.action_back))
            }
        },
        actions = { actions() },
        colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
    )
}

/** Content no wider than reads well, centred on a wide screen. */
@Composable
fun Readable(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Box(modifier.fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
        Column(Modifier.widthIn(max = Space.maxContent).fillMaxWidth(), content = content)
    }
}

@Composable
fun SectionTitle(text: String, modifier: Modifier = Modifier, trailing: String? = null) {
    Row(
        modifier.fillMaxWidth().padding(start = Space.l, end = Space.l, top = Space.xl, bottom = Space.s),
        verticalAlignment = Alignment.Bottom,
    ) {
        Text(
            text, Modifier.weight(1f).semantics { heading() },
            style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (trailing != null) {
            Text(trailing, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** A card on the background, outlined rather than raised, as the website draws its panels. */
@Composable
fun Panel(modifier: Modifier = Modifier, color: Color = MaterialTheme.colorScheme.surface, content: @Composable ColumnScope.() -> Unit) {
    Surface(
        modifier.fillMaxWidth().padding(horizontal = Space.l),
        shape = MaterialTheme.shapes.large,
        color = color,
        border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    ) {
        Column(Modifier.padding(vertical = Space.xs), content = content)
    }
}

/** A labelled value that copies itself when tapped, as an address is. */
@Composable
fun CopyRow(label: String, value: String, copied: (String) -> Unit, modifier: Modifier = Modifier) {
    val clipboard = LocalClipboard.current
    val scope = rememberCoroutineScope()
    val haptics = LocalHapticFeedback.current
    val copyLabel = stringResource(R.string.action_copy_value, label)
    Row(
        modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClickLabel = copyLabel) {
                scope.launch { clipboard.setClipEntry(ClipEntry(ClipData.newPlainText(label, value))) }
                haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                copied(label)
            }
            .padding(horizontal = Space.l, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Address(value)
        }
        Icon(painterResource(R.drawable.ic_copy), null, Modifier.size(18.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/**
 * An address or a key in the monospace face: shrunk to one line where it
 * fits, and else broken after a colon or a dot, never inside a group.
 */
@Composable
fun Address(value: String, modifier: Modifier = Modifier) {
    var wrap by remember(value) { mutableStateOf(false) }
    val style = MonoBody.copy(color = MaterialTheme.colorScheme.onSurface)
    if (wrap) {
        Text(value.replace(":", ":\u200B").replace(".", ".\u200B"), modifier, style = style)
    } else {
        BasicText(
            value, modifier, style = style, maxLines = 1,
            autoSize = TextAutoSize.StepBased(minFontSize = 12.sp, maxFontSize = MonoBody.fontSize),
            onTextLayout = { if (it.hasVisualOverflow) wrap = true },
        )
    }
}

/** A labelled value in a panel. */
@Composable
fun InfoRow(label: String, value: String, modifier: Modifier = Modifier, valueColor: Color = Color.Unspecified) {
    Column(modifier.fillMaxWidth().padding(horizontal = Space.l, vertical = Space.m)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        val color = if (valueColor == Color.Unspecified) MaterialTheme.colorScheme.onSurface else valueColor
        Text(value, style = MaterialTheme.typography.bodyLarge, color = color)
    }
}

/** A small rounded label, as for a member's roles. */
@Composable
fun Tag(text: String, modifier: Modifier = Modifier) {
    Text(
        text,
        modifier
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, MaterialTheme.shapes.extraSmall)
            .padding(horizontal = 6.dp, vertical = 1.dp),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

/** A big circular badge around an icon, to open a screen with. */
@Composable
fun IconBadge(painter: androidx.compose.ui.graphics.painter.Painter, tint: Color, background: Color, modifier: Modifier = Modifier) {
    Box(
        modifier.size(72.dp).clip(CircleShape).background(background),
        contentAlignment = Alignment.Center,
    ) {
        Icon(painter, null, Modifier.size(36.dp), tint = tint)
    }
}

