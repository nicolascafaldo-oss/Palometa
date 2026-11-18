package com.example.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

@Immutable
data class DexScopeSyntaxColors(
    val opcode: Color,
    val register: Color,
    val stringLiteral: Color,
    val nativeTag: Color,
    val addressOffset: Color,
    val dexSegment: Color,
    val elfSegment: Color,
    val resourceSegment: Color,
    val otherSegment: Color,
    val borderSubtle: Color
)

val LocalDexScopeSyntax = staticCompositionLocalOf {
    DexScopeSyntaxColors(
        opcode = SignalAmber,
        register = PhosphorCyan,
        stringLiteral = EmeraldMint,
        nativeTag = CoralRed,
        addressOffset = TextSecondaryDark,
        dexSegment = PhosphorCyan,
        elfSegment = CoralRed,
        resourceSegment = SignalAmber,
        otherSegment = VioletByte,
        borderSubtle = HairlineBorder
    )
}

private val DarkSyntaxColors = DexScopeSyntaxColors(
    opcode = AmberSoft,
    register = CyanSoft,
    stringLiteral = EmeraldMint,
    nativeTag = CoralRed,
    addressOffset = TextSecondaryDark,
    dexSegment = PhosphorCyan,
    elfSegment = CoralRed,
    resourceSegment = SignalAmber,
    otherSegment = VioletByte,
    borderSubtle = HairlineBorder
)

private val LightSyntaxColors = DexScopeSyntaxColors(
    opcode = AmberLightSecondary,
    register = CyanLightPrimary,
    stringLiteral = EmeraldLightTertiary,
    nativeTag = CoralLightError,
    addressOffset = TextSecondaryLight,
    dexSegment = CyanLightPrimary,
    elfSegment = CoralLightError,
    resourceSegment = AmberLightSecondary,
    otherSegment = Color(0xFF7C3AED),
    borderSubtle = LightBorder
)

private val DexScopeDarkColorScheme = darkColorScheme(
    primary = PhosphorCyan,
    onPrimary = ObsidianBg,
    primaryContainer = CyanMuted,
    onPrimaryContainer = CyanSoft,
    secondary = SignalAmber,
    onSecondary = ObsidianBg,
    secondaryContainer = AmberMuted,
    onSecondaryContainer = AmberSoft,
    tertiary = EmeraldMint,
    onTertiary = ObsidianBg,
    tertiaryContainer = EmeraldMuted,
    onTertiaryContainer = EmeraldMint,
    error = CoralRed,
    onError = ObsidianBg,
    errorContainer = CoralMuted,
    onErrorContainer = CoralRed,
    background = ObsidianBg,
    onBackground = TextPrimaryDark,
    surface = GraphiteSurface,
    onSurface = TextPrimaryDark,
    surfaceVariant = SlateElevated,
    onSurfaceVariant = TextSecondaryDark,
    outline = HairlineBorder,
    outlineVariant = Color(0xFF21262D)
)

private val DexScopeLightColorScheme = lightColorScheme(
    primary = CyanLightPrimary,
    onPrimary = Color.White,
    primaryContainer = CyanLightContainer,
    onPrimaryContainer = Color(0xFF0C4A6E),
    secondary = AmberLightSecondary,
    onSecondary = Color.White,
    secondaryContainer = AmberLightContainer,
    onSecondaryContainer = Color(0xFF78350F),
    tertiary = EmeraldLightTertiary,
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFD1FAE5),
    onTertiaryContainer = Color(0xFF065F46),
    error = CoralLightError,
    onError = Color.White,
    errorContainer = Color(0xFFFFE4E6),
    onErrorContainer = Color(0xFF9F1239),
    background = LightCanvas,
    onBackground = TextPrimaryLight,
    surface = LightSurface,
    onSurface = TextPrimaryLight,
    surfaceVariant = LightElevated,
    onSurfaceVariant = TextSecondaryLight,
    outline = LightBorder,
    outlineVariant = Color(0xFFE5E9F0)
)

val DexScopeShapes = Shapes(
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(12.dp),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(20.dp)
)

@Composable
fun DexScopeTheme(
    darkTheme: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DexScopeDarkColorScheme else DexScopeLightColorScheme
    val syntaxColors = if (darkTheme) DarkSyntaxColors else LightSyntaxColors

    CompositionLocalProvider(LocalDexScopeSyntax provides syntaxColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = DexScopeTypography,
            shapes = DexScopeShapes,
            content = content
        )
    }
}
