package io.juist.app.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import io.juist.app.R

/** IBM Plex, as design/tokens.json names it. */
val PlexSans = FontFamily(
    Font(R.font.plex_sans_regular, FontWeight.Normal),
    Font(R.font.plex_sans_medium, FontWeight.Medium),
    Font(R.font.plex_sans_semibold, FontWeight.SemiBold),
)

val PlexMono = FontFamily(
    Font(R.font.plex_mono_regular, FontWeight.Normal),
    Font(R.font.plex_mono_medium, FontWeight.Medium),
    Font(R.font.plex_mono_semibold, FontWeight.SemiBold),
)

private fun style(size: Int, line: Int, weight: FontWeight, tracking: Double = 0.0) = TextStyle(
    fontFamily = PlexSans, fontWeight = weight, fontSize = size.sp, lineHeight = line.sp, letterSpacing = tracking.em,
)

val JuistTypography = Typography(
    displayLarge = style(52, 60, FontWeight.SemiBold, -0.02),
    displayMedium = style(44, 52, FontWeight.SemiBold, -0.02),
    displaySmall = style(36, 44, FontWeight.SemiBold, -0.01),
    headlineLarge = style(32, 40, FontWeight.SemiBold, -0.01),
    headlineMedium = style(28, 36, FontWeight.SemiBold),
    headlineSmall = style(24, 32, FontWeight.SemiBold),
    titleLarge = style(22, 28, FontWeight.SemiBold),
    titleMedium = style(16, 24, FontWeight.SemiBold, 0.005),
    titleSmall = style(14, 20, FontWeight.Medium, 0.005),
    bodyLarge = style(16, 24, FontWeight.Normal),
    bodyMedium = style(14, 20, FontWeight.Normal),
    bodySmall = style(12, 16, FontWeight.Normal, 0.01),
    labelLarge = style(14, 20, FontWeight.Medium, 0.01),
    labelMedium = style(12, 16, FontWeight.Medium, 0.02),
    labelSmall = style(11, 16, FontWeight.Medium, 0.03),
)

/** Addresses, keys and words to compare: what is read character by character. */
val MonoBody = TextStyle(fontFamily = PlexMono, fontWeight = FontWeight.Normal, fontSize = 15.sp, lineHeight = 22.sp)

val MonoWords = TextStyle(fontFamily = PlexMono, fontWeight = FontWeight.SemiBold, fontSize = 30.sp, lineHeight = 38.sp)
