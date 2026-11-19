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
        opcode = MutedTangerine,
        register = MutedCoralRed,
        stringLiteral = MutedDustyPink,
        nativeTag = MutedCoralRed,
        addressOffset = WarmTaupeSecondary,
        dexSegment = MutedCoralRed,
        elfSegment = MutedDustyPink,
        resourceSegment = MutedOchreYellow,
        otherSegment = MutedPlumPurple,
        borderSubtle = WarmLinenBorder
    )
}

private val LightSyntaxColors = DexScopeSyntaxColors(
    opcode = MutedTangerine,
    register = MutedCoralRed,
    stringLiteral = MutedDustyPink,
    nativeTag = MutedCoralRed,
    addressOffset = WarmTaupeSecondary,
    dexSegment = MutedCoralRed,
    elfSegment = MutedDustyPink,
    resourceSegment = MutedOchreYellow,
    otherSegment = MutedPlumPurple,
    borderSubtle = WarmLinenBorder
)

private val DarkSyntaxColors = DexScopeSyntaxColors(
    opcode = SoftApricotOrangeDark,
    register = SoftCoralRedDark,
    stringLiteral = SoftMustardYellowDark,
    nativeTag = SoftRosePinkDark,
    addressOffset = WarmSandTextDark,
    dexSegment = SoftCoralRedDark,
    elfSegment = SoftRosePinkDark,
    resourceSegment = SoftMustardYellowDark,
    otherSegment = SoftLavenderPlumDark,
    borderSubtle = DuskBorder
)

private val PalometaLightColorScheme = lightColorScheme(
    primary = MutedCoralRed,
    onPrimary = Color.White,
    primaryContainer = CoralBlushContainer,
    onPrimaryContainer = OnCoralBlush,
    secondary = MutedTangerine,
    onSecondary = Color.White,
    secondaryContainer = TangerineSoftContainer,
    onSecondaryContainer = OnTangerineSoft,
    tertiary = MutedDustyPink,
    onTertiary = Color.White,
    tertiaryContainer = DustyPinkContainer,
    onTertiaryContainer = OnDustyPink,
    error = Color(0xFFB33F40),
    onError = Color.White,
    errorContainer = Color(0xFFFAD6D6),
    onErrorContainer = Color(0xFF5C1B1C),
    background = WarmCreamBg,
    onBackground = WarmInkPrimary,
    surface = WarmIvorySurface,
    onSurface = WarmInkPrimary,
    surfaceVariant = WarmBlushElevated,
    onSurfaceVariant = WarmTaupeSecondary,
    outline = WarmLinenBorder,
    outlineVariant = Color(0xFFECE0DA)
)

private val PalometaDarkColorScheme = darkColorScheme(
    primary = SoftCoralRedDark,
    onPrimary = DuskPlumBg,
    primaryContainer = CoralContainerDark,
    onPrimaryContainer = OnCoralContainerDark,
    secondary = SoftApricotOrangeDark,
    onSecondary = DuskPlumBg,
    secondaryContainer = ApricotContainerDark,
    onSecondaryContainer = OnApricotContainerDark,
    tertiary = SoftRosePinkDark,
    onTertiary = DuskPlumBg,
    tertiaryContainer = RoseContainerDark,
    onTertiaryContainer = OnRoseContainerDark,
    error = SoftCoralRedDark,
    onError = DuskPlumBg,
    errorContainer = CoralContainerDark,
    onErrorContainer = OnCoralContainerDark,
    background = DuskPlumBg,
    onBackground = WarmCreamTextDark,
    surface = DuskCocoaSurface,
    onSurface = WarmCreamTextDark,
    surfaceVariant = DuskMauveElevated,
    onSurfaceVariant = WarmSandTextDark,
    outline = DuskBorder,
    outlineVariant = Color(0xFF392D36)
)

val DexScopeShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(18.dp),
    extraLarge = RoundedCornerShape(22.dp)
)

@Composable
fun DexScopeTheme(
    darkTheme: Boolean = false,
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) PalometaDarkColorScheme else PalometaLightColorScheme
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
