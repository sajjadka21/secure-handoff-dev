package org.clipbridge.android

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.clipbridge.android.core.AndroidIdentityStore
import org.clipbridge.android.core.SafeIdentityMetadata

private enum class Destination(val title: String, val icon: ImageVector) {
    Home("Home", Icons.Outlined.Home),
    Devices("Devices", Icons.Outlined.Devices),
    Activity("Activity", Icons.Outlined.History),
    Settings("Settings", Icons.Outlined.Settings),
}

private sealed interface IdentityState {
    data object Loading : IdentityState
    data class Ready(val metadata: SafeIdentityMetadata) : IdentityState
    data class Unavailable(val reason: String) : IdentityState
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val preferences = getSharedPreferences("preferences", Context.MODE_PRIVATE)
        var identityState by mutableStateOf<IdentityState>(IdentityState.Loading)
        lifecycleScope.launch {
            identityState = try {
                withContext(Dispatchers.IO) {
                    AndroidIdentityStore(applicationContext).loadOrCreate()
                }.let { IdentityState.Ready(it) }
            } catch (_: Exception) {
                IdentityState.Unavailable("Secure identity is unavailable. Check Android Keystore and restart the app.")
            }
        }
        setContent {
            val dark = preferences.getString("appearance", "system") == "dark" ||
                (preferences.getString("appearance", "system") == "system" && androidx.compose.foundation.isSystemInDarkTheme())
            var appearance by rememberSaveable { mutableStateOf(preferences.getString("appearance", "system") ?: "system") }
            ClipBridgeTheme(darkTheme = dark) {
                var selected by rememberSaveable { mutableStateOf(Destination.Home.name) }
                var paused by rememberSaveable { mutableStateOf(preferences.getBoolean("privacy_paused", false)) }
                val destination = Destination.valueOf(selected)
                Scaffold(
                    bottomBar = {
                        NavigationBar {
                            Destination.entries.forEach { item ->
                                NavigationBarItem(
                                    selected = destination == item,
                                    onClick = { selected = item.name },
                                    icon = { androidx.compose.material3.Icon(item.icon, contentDescription = item.title) },
                                    label = { Text(item.title) },
                                )
                            }
                        }
                    },
                ) { padding ->
                    when (destination) {
                        Destination.Home -> HomeScreen(
                            padding = padding,
                            context = this@MainActivity,
                            identityState = identityState,
                            paused = paused,
                            onPause = {
                                paused = !paused
                                preferences.edit().putBoolean("privacy_paused", paused).apply()
                            },
                        )
                        Destination.Devices -> DevicesScreen(padding, identityState)
                        Destination.Activity -> ActivityScreen(padding)
                        Destination.Settings -> SettingsScreen(
                            padding = padding,
                            paused = paused,
                            onPause = {
                                paused = !paused
                                preferences.edit().putBoolean("privacy_paused", paused).apply()
                            },
                            onAppearance = { appearance = it; preferences.edit().putString("appearance", it).apply() },
                            appearance = appearance,
                            identityState = identityState,
                            context = this@MainActivity,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun HomeScreen(
    padding: PaddingValues,
    context: Context,
    identityState: IdentityState,
    paused: Boolean,
    onPause: () -> Unit,
) {
    var tab by rememberSaveable { mutableStateOf(0) }
    var composeText by remember { mutableStateOf("") }
    var clipboardText by remember { mutableStateOf<String?>(null) }
    var clipboardError by remember { mutableStateOf<String?>(null) }
    var clipboardReadAttempted by remember { mutableStateOf(false) }
    Column(
        Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("ClipBridge", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
        StatusCard(identityState, paused)
        if (paused) {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer)) {
                Row(Modifier.fillMaxWidth().padding(16.dp), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text("Privacy Pause is on", style = MaterialTheme.typography.titleSmall)
                    OutlinedButton(onClick = onPause) { Text("Resume") }
                }
            }
        }
        TabRow(selectedTabIndex = tab) {
            listOf("Clipboard", "Compose").forEachIndexed { index, label ->
                Tab(selected = tab == index, onClick = { tab = index }, text = { Text(label) })
            }
        }
        if (tab == 0) {
            Text("Read the clipboard explicitly to preview it. Sending becomes available after pairing and LAN are integrated.", style = MaterialTheme.typography.bodyMedium)
            OutlinedButton(onClick = {
                clipboardReadAttempted = true
                clipboardError = null
                clipboardText = try {
                    val manager = context.getClipboardManager()
                    manager.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString()
                } catch (_: SecurityException) {
                    clipboardError = "Android limited clipboard access. Keep ClipBridge open and tap Read Clipboard again."
                    null
                }
            }, modifier = Modifier.fillMaxWidth()) { Text("Read Clipboard") }
            clipboardError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            clipboardText?.let { content ->
                Card {
                    Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Preview · ${TextClassifier.classify(content)}", style = MaterialTheme.typography.labelLarge)
                        Text(content.take(600), style = MaterialTheme.typography.bodyMedium)
                        Text("${content.toByteArray(Charsets.UTF_8).size} bytes", style = MaterialTheme.typography.labelMedium)
                    }
                }
            } ?: Text(
                if (clipboardReadAttempted) "Clipboard is empty or Android did not make it available while ClipBridge was focused."
                else "Not read",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(onClick = {}, enabled = false, modifier = Modifier.fillMaxWidth()) { Text("Send") }
            Text("Pairing and LAN transfer are not connected in this build.", style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = {
                clipboardText?.let { context.copyToClipboard("ClipBridge text", it) }
            }, enabled = clipboardText != null, modifier = Modifier.fillMaxWidth()) { Text("Copy") }
            OutlinedButton(onClick = { clipboardText = null; clipboardError = null; clipboardReadAttempted = false }, modifier = Modifier.fillMaxWidth()) { Text("Clear") }
        } else {
            Text("Compose a one-time handoff. Text is not saved as activity or history.", style = MaterialTheme.typography.bodyMedium)
            OutlinedTextField(
                value = composeText,
                onValueChange = { composeText = it },
                modifier = Modifier.fillMaxWidth().height(220.dp),
                label = { Text("Text to send") },
                supportingText = {
                    Text("${composeText.toByteArray(Charsets.UTF_8).size} bytes · ${TextClassifier.classify(composeText)}")
                },
                minLines = 6,
            )
            Button(onClick = {}, enabled = false, modifier = Modifier.fillMaxWidth()) { Text("Send") }
            Text("A trusted device and an authenticated LAN session are required. This build does not yet provide pairing or transfer.", style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = { composeText = "" }, modifier = Modifier.fillMaxWidth()) { Text("Clear") }
        }
    }
}

@Composable
private fun StatusCard(identityState: IdentityState, paused: Boolean) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(if (paused) "Paused" else "Setup incomplete", style = MaterialTheme.typography.titleMedium)
            when (identityState) {
                IdentityState.Loading -> Text("Loading protected device identity…")
                is IdentityState.Ready -> Text("Android · identity ${identityState.metadata.shortFingerprint} · LAN transfer unavailable")
                is IdentityState.Unavailable -> Text(identityState.reason, color = MaterialTheme.colorScheme.error)
            }
            Text("Transport availability does not mean a device is trusted.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun DevicesScreen(padding: PaddingValues, identityState: IdentityState) {
    Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("Devices", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
        Text("Trusted devices", style = MaterialTheme.typography.titleMedium)
        Text("Trusted-device storage is not connected in this build.", style = MaterialTheme.typography.bodyLarge)
        Card {
            Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Add a device", style = MaterialTheme.typography.titleSmall)
            Text("Pairing and the trust database are not connected in this build. No nearby device is shown as trusted.")
                Button(onClick = {}, enabled = false, modifier = Modifier.fillMaxWidth()) { Text("Pairing unavailable") }
            }
        }
    }
}

@Composable
private fun ActivityScreen(padding: PaddingValues) {
    Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Activity", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
        Text("Activity contains transfer metadata only. Content history is off.", style = MaterialTheme.typography.bodyMedium)
        HorizontalDivider()
        Text("No activity yet.", color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun SettingsScreen(
    padding: PaddingValues,
    paused: Boolean,
    onPause: () -> Unit,
    onAppearance: (String) -> Unit,
    appearance: String,
    identityState: IdentityState,
    context: Context,
) {
    var section by rememberSaveable { mutableStateOf("Settings") }
    var diagnosticsCopied by rememberSaveable { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(section, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
        if (section == "Settings") {
            Card {
                Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Privacy & Security", style = MaterialTheme.typography.titleMedium)
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) { Text("Privacy Pause"); Text("Blocks new pairing and transfer when those flows are available.", style = MaterialTheme.typography.bodySmall) }
                        Switch(
                            checked = paused,
                            onCheckedChange = { onPause() },
                            modifier = Modifier.size(48.dp).semantics { contentDescription = "Privacy Pause" },
                        )
                    }
                    Text("Auto-sync · Off", style = MaterialTheme.typography.bodyMedium)
                    Text("Clipboard history · Off", style = MaterialTheme.typography.bodyMedium)
                }
            }
            Card {
                Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Appearance", style = MaterialTheme.typography.titleMedium)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf("system", "light", "dark").forEach { mode ->
                            OutlinedButton(onClick = { onAppearance(mode) }) { Text(mode.replaceFirstChar { it.uppercase() }) }
                        }
                    }
                }
            }
            OutlinedButton(onClick = { section = "Help & Diagnostics" }, modifier = Modifier.fillMaxWidth()) { Text("Help & diagnostics") }
            Text("Android build foundation · pairing and LAN transfer are not available yet.", style = MaterialTheme.typography.bodySmall)
        } else {
            OutlinedButton(onClick = { section = "Settings" }, modifier = Modifier.fillMaxWidth()) { Text("Back to Settings") }
            Text("Help", style = MaterialTheme.typography.titleMedium)
            Text("Android reads clipboard data only while this app is focused. Use Read Clipboard after opening ClipBridge; no background polling is performed.")
            Text("Pairing, trusted-device management, and LAN troubleshooting will appear when those Rust-backed flows are integrated.")
            HorizontalDivider()
            Text("Diagnostics", style = MaterialTheme.typography.titleMedium)
            val identity = when (identityState) {
                IdentityState.Loading -> "loading"
                is IdentityState.Ready -> "protected_identity_ready"
                is IdentityState.Unavailable -> "protected_identity_unavailable"
            }
            val report = "app_version=0.1.0\nos=Android\nprotocol_version=1\nidentity=$identity\ntrust_store=unavailable\nroute=unavailable\nsession=inactive\nprivacy_paused=$paused"
            Text(report, style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = {
                context.copyToClipboard("ClipBridge diagnostics", report)
                diagnosticsCopied = true
            }, modifier = Modifier.fillMaxWidth()) { Text(if (diagnosticsCopied) "Copied redacted diagnostics" else "Copy redacted diagnostics") }
        }
    }
}

private fun Context.getClipboardManager(): ClipboardManager =
    getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

private fun Context.copyToClipboard(label: String, text: String) {
    getClipboardManager().setPrimaryClip(ClipData.newPlainText(label, text))
}

@Composable
private fun ClipBridgeTheme(darkTheme: Boolean, content: @Composable () -> Unit) {
    val colors = if (darkTheme) {
        androidx.compose.material3.darkColorScheme(
            primary = androidx.compose.ui.graphics.Color(0xFFA8C7FA),
            onPrimary = androidx.compose.ui.graphics.Color(0xFF102C52),
            surface = androidx.compose.ui.graphics.Color(0xFF111318),
            surfaceContainerLow = androidx.compose.ui.graphics.Color(0xFF1A1D23),
        )
    } else {
        androidx.compose.material3.lightColorScheme(
            primary = androidx.compose.ui.graphics.Color(0xFF315DA8),
            onPrimary = androidx.compose.ui.graphics.Color.White,
            surface = androidx.compose.ui.graphics.Color(0xFFF7F8FA),
            surfaceContainerLow = androidx.compose.ui.graphics.Color(0xFFFFFFFF),
        )
    }
    MaterialTheme(colorScheme = colors, content = content)
}
