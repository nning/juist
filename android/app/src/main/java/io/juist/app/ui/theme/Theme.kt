package io.juist.app.ui.theme

import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.unit.dp

/** Spacing, on a 4 dp grid. */
object Space {
    val xs = 4.dp
    val s = 8.dp
    val m = 12.dp
    val l = 16.dp
    val xl = 24.dp
    val xxl = 32.dp
    val xxxl = 48.dp

    /** How wide content grows on a tablet or in landscape before it is centred. */
    val maxContent = 600.dp
}

/** Durations and easing, the same throughout. */
object Motion {
    const val SHORT = 150
    const val MEDIUM = 250
    const val LONG = 400
    val emphasized = CubicBezierEasing(0.2f, 0f, 0f, 1f)
}

val JuistShapes = Shapes(
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(20.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

/** A member's reach and an alarm, coloured as the website colours them. */
class StatusColors(val direct: Color, val relay: Color, val sought: Color, val absent: Color, val alarm: Color)

val LocalStatusColors = staticCompositionLocalOf { statusColors(DayStatus) }

private fun statusColors(p: StatusPalette) = StatusColors(p.direct, p.relay, p.sought, p.absent, p.alarm)

/**
 * The scheme from design/tokens.json. Roles the tokens leave out are mixed from
 * theirs, never Material's own purple defaults.
 */
internal fun colorScheme(p: Palette, other: Palette, dark: Boolean): ColorScheme {
    fun container(c: Color) = lerp(p.surface, c, if (dark) 0.22f else 0.14f)
    fun onContainer(c: Color) = lerp(p.onSurface, c, if (dark) 0.25f else 0.55f)
    val low = lerp(p.surface, p.surfaceVariant, 0.35f)
    val mid = lerp(p.surface, p.surfaceVariant, 0.6f)
    val high = lerp(p.surface, p.surfaceVariant, 0.85f)
    val base = if (dark) darkColorScheme() else lightColorScheme()
    return base.copy(
        primary = p.primary, onPrimary = p.onPrimary,
        primaryContainer = p.primaryContainer, onPrimaryContainer = p.onPrimaryContainer,
        inversePrimary = other.primary,
        secondary = p.secondary, onSecondary = p.onSecondary,
        secondaryContainer = container(p.secondary), onSecondaryContainer = onContainer(p.secondary),
        tertiary = p.tertiary, onTertiary = p.onTertiary,
        tertiaryContainer = container(p.tertiary), onTertiaryContainer = onContainer(p.tertiary),
        background = p.background, onBackground = p.onBackground,
        surface = p.surface, onSurface = p.onSurface,
        surfaceVariant = p.surfaceVariant, onSurfaceVariant = p.onSurfaceVariant,
        surfaceTint = p.primary,
        inverseSurface = p.onSurface, inverseOnSurface = p.surface,
        error = p.error, onError = p.onError,
        errorContainer = container(p.error), onErrorContainer = onContainer(p.error),
        outline = p.outline, outlineVariant = p.outlineVariant,
        scrim = Color.Black,
        surfaceBright = p.surface, surfaceDim = p.surfaceVariant,
        surfaceContainerLowest = if (dark) p.background else p.surface,
        surfaceContainerLow = low, surfaceContainer = mid, surfaceContainerHigh = high,
        surfaceContainerHighest = p.surfaceVariant,
        primaryFixed = p.primaryContainer, primaryFixedDim = p.primaryContainer,
        onPrimaryFixed = p.onPrimaryContainer, onPrimaryFixedVariant = p.onPrimaryContainer,
        secondaryFixed = container(p.secondary), secondaryFixedDim = container(p.secondary),
        onSecondaryFixed = onContainer(p.secondary), onSecondaryFixedVariant = onContainer(p.secondary),
        tertiaryFixed = container(p.tertiary), tertiaryFixedDim = container(p.tertiary),
        onTertiaryFixed = onContainer(p.tertiary), onTertiaryFixedVariant = onContainer(p.tertiary),
    )
}

@Composable
fun JuistTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    val scheme = if (dark) colorScheme(NightPalette, DayPalette, true) else colorScheme(DayPalette, NightPalette, false)
    CompositionLocalProvider(LocalStatusColors provides statusColors(if (dark) NightStatus else DayStatus)) {
        MaterialTheme(colorScheme = scheme, typography = JuistTypography, shapes = JuistShapes, content = content)
    }
}
