package org.clipbridge.android

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
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
import androidx.compose.runtime.DisposableEffect
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
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.barcode.common.Barcode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import org.clipbridge.android.core.AndroidIdentityStore
import org.clipbridge.android.core.AndroidTrustStore
import org.clipbridge.android.core.ActivityKind
import org.clipbridge.android.core.ActivityResult
import org.clipbridge.android.core.ActivityStore
import org.clipbridge.android.core.SafeDiagnostics
import org.clipbridge.android.core.serializeDiagnostics
import org.clipbridge.android.core.NativeCore
import org.clipbridge.android.core.SafeIdentityMetadata
import org.clipbridge.android.core.TrustedDeviceMetadata

private enum class Destination(val title: String, val icon: ImageVector) {
    Home("Home", Icons.Outlined.Home),
    Devices("Devices", Icons.Outlined.Devices),
    Activity("Activity", Icons.Outlined.History),
    Settings("Settings", Icons.Outlined.Settings),
}

private sealed interface IdentityState {
    data object Loading : IdentityState
    data class Ready(val metadata: SafeIdentityMetadata, val trustStore: AndroidTrustStore) : IdentityState
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
                    val metadata = AndroidIdentityStore(applicationContext).loadOrCreate()
                    val trustStore = AndroidTrustStore(applicationContext)
                    NativeCore.requireAvailable()
                    check(trustStore.open()) { "trust_store_unavailable" }
                    NativeCore.nativeSetPrivacyPaused(preferences.getBoolean("privacy_paused", false))
                    IdentityState.Ready(metadata, trustStore)
                }
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
                            trustStore = (identityState as? IdentityState.Ready)?.trustStore,
                            paused = paused,
                            onPause = {
                                paused = !paused
                                preferences.edit().putBoolean("privacy_paused", paused).apply()
                                runCatching { NativeCore.nativeSetPrivacyPaused(paused) }
                            },
                        )
                        Destination.Devices -> DevicesScreen(padding, identityState, this@MainActivity, paused)
                        Destination.Activity -> ActivityScreen(padding, this@MainActivity)
                        Destination.Settings -> SettingsScreen(
                            padding = padding,
                            paused = paused,
                            onPause = {
                                paused = !paused
                                preferences.edit().putBoolean("privacy_paused", paused).apply()
                                runCatching { NativeCore.nativeSetPrivacyPaused(paused) }
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
    trustStore: AndroidTrustStore?,
    paused: Boolean,
    onPause: () -> Unit,
) {
    var tab by rememberSaveable { mutableStateOf(0) }
    var composeText by remember { mutableStateOf("") }
    var clipboardText by remember { mutableStateOf<String?>(null) }
    var clipboardError by remember { mutableStateOf<String?>(null) }
    var clipboardReadAttempted by remember { mutableStateOf(false) }
    var devices by remember { mutableStateOf(emptyList<TrustedDeviceMetadata>()) }
    var selectedDeviceId by rememberSaveable { mutableStateOf("") }
    var endpoint by rememberSaveable { mutableStateOf("") }
    var targetExpanded by remember { mutableStateOf(false) }
    var sending by remember { mutableStateOf(false) }
    var sendStatus by remember { mutableStateOf<String?>(null) }
    var receiveEndpoint by remember { mutableStateOf<String?>(null) }
    var receivedText by remember { mutableStateOf<Pair<String, String>?>(null) }
    val activityStore = remember(context) { ActivityStore(context) }
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val stopReceiver = {
            runCatching { NativeCore.nativeStopReceiver() }
            context.getSharedPreferences("runtime", Context.MODE_PRIVATE)
                .edit().putBoolean("receiver_active", false).apply()
            receiveEndpoint = null
        }
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) {
                stopReceiver()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            stopReceiver()
        }
    }
    androidx.compose.runtime.LaunchedEffect(trustStore) {
        devices = trustStore?.let { runCatching { it.list() }.getOrDefault(emptyList()) } ?: emptyList()
    }
    val selectedDevice = devices.firstOrNull { it.deviceId.joinToString("") { byte -> "%02x".format(byte) } == selectedDeviceId }
    val startReceiver = {
        val address = context.activeLanIpv4()
        if (address == null) sendStatus = "No active Wi-Fi or Ethernet LAN address is available."
        else scope.launch {
            receiveEndpoint = withContext(Dispatchers.IO) { NativeCore.nativeStartReceiver("$address:0") }
            context.getSharedPreferences("runtime", Context.MODE_PRIVATE).edit().putBoolean("receiver_active", receiveEndpoint != null).apply()
            if (receiveEndpoint == null) sendStatus = "Could not start the foreground LAN receiver. Check the active Wi-Fi or Ethernet connection."
        }
    }
    androidx.compose.runtime.LaunchedEffect(receiveEndpoint, paused) {
        if (receiveEndpoint != null && !paused) {
            while (isActive) {
                val frame = withContext(Dispatchers.IO) { NativeCore.nativeReceiveText() }
                if (frame != null) {
                    runCatching { decodeIncoming(frame) }.onSuccess {
                        receivedText = it
                        activityStore.record(ActivityKind.TEXT_RECEIVED, it.first, "LAN Direct", ActivityResult.SUCCESS)
                    }
                    frame.fill(0)
                } else delay(350)
            }
        }
    }
    fun send(text: String) {
        if (paused) { sendStatus = "Privacy Pause is on. Resume before sending."; return }
        val device = selectedDevice ?: run { sendStatus = "Choose a trusted device first."; return }
        if (device.needsRepair) { sendStatus = "This device needs repair. Revoke it and pair again."; return }
        sending = true
        sendStatus = "Connecting · LAN Direct · encrypted application session"
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { NativeCore.nativeSendText(endpoint, device.deviceId, text) ?: "connection_failed" }
                    .getOrElse { "connection_failed" }
            }
            sending = false
            context.getSharedPreferences("runtime", Context.MODE_PRIVATE).edit()
                .putString("last_error", if (result == "sent") "none" else result)
                .apply()
            activityStore.record(
                if (result == "sent") ActivityKind.TEXT_SENT else ActivityKind.CONNECTION_FAILED,
                device.label,
                if (result == "sent") "LAN Direct" else "unknown",
                if (result == "sent") ActivityResult.SUCCESS else ActivityResult.FAILED,
            )
            sendStatus = when (result) {
                "sent" -> "Sent · Encrypted · LAN Direct"
                "privacy_paused" -> "Privacy Pause is on. Resume before sending."
                "peer_untrusted" -> "This device is not trusted. Pair it first."
                "payload_too_large" -> "Text is larger than the supported limit."
                else -> "Send failed · Check the address, trust state, and LAN connection."
            }
        }
    }
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
        Text("Destination", style = MaterialTheme.typography.titleSmall)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = startReceiver, enabled = receiveEndpoint == null && !paused, modifier = Modifier.weight(1f)) { Text("Enable receiving") }
            if (receiveEndpoint != null) OutlinedButton(onClick = {
                runCatching { NativeCore.nativeStopReceiver() }
                context.getSharedPreferences("runtime", Context.MODE_PRIVATE).edit().putBoolean("receiver_active", false).apply()
                receiveEndpoint = null
            }) { Text("Stop") }
        }
        receiveEndpoint?.let { Text("Foreground receiver active · $it", style = MaterialTheme.typography.bodySmall) }
        OutlinedButton(onClick = { targetExpanded = true }, enabled = devices.isNotEmpty(), modifier = Modifier.fillMaxWidth()) {
            Text(selectedDevice?.label ?: if (devices.isEmpty()) "No trusted devices" else "Choose a trusted device")
        }
        DropdownMenu(expanded = targetExpanded, onDismissRequest = { targetExpanded = false }) {
            devices.forEach { device ->
                DropdownMenuItem(text = { Text("${device.label}${if (device.needsRepair) " · Needs repair" else ""}") }, onClick = {
                    selectedDeviceId = device.deviceId.joinToString("") { "%02x".format(it) }
                    targetExpanded = false
                })
            }
        }
        OutlinedTextField(value = endpoint, onValueChange = { endpoint = it.take(128) }, label = { Text("Trusted device LAN address") }, placeholder = { Text("192.168.1.20:45678") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        if (tab == 0) {
            Text("Read the clipboard explicitly to preview it. ClipBridge never polls in the background.", style = MaterialTheme.typography.bodyMedium)
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
            Button(onClick = { clipboardText?.let(::send) }, enabled = clipboardText != null && selectedDevice != null && endpoint.isNotBlank() && !sending && !paused, modifier = Modifier.fillMaxWidth()) { Text(if (sending) "Sending…" else "Send Clipboard") }
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
            Button(onClick = { send(composeText) }, enabled = composeText.isNotEmpty() && selectedDevice != null && endpoint.isNotBlank() && !sending && !paused, modifier = Modifier.fillMaxWidth()) { Text(if (sending) "Sending…" else "Send") }
            Text("${composeText.toByteArray(Charsets.UTF_8).size} bytes · ${TextClassifier.classify(composeText)}", style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = { composeText = "" }, modifier = Modifier.fillMaxWidth()) { Text("Clear") }
        }
        sendStatus?.let { Text(it, color = if (it.startsWith("Sent")) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall) }
    }
    receivedText?.let { (sender, text) ->
        AlertDialog(
            onDismissRequest = { receivedText = null },
            title = { Text("Text received from $sender") },
            text = { Text(text.take(6000), style = MaterialTheme.typography.bodyMedium) },
            confirmButton = { Button(onClick = { context.copyToClipboard("ClipBridge received text", text); receivedText = null }) { Text("Copy") } },
            dismissButton = { OutlinedButton(onClick = { receivedText = null }) { Text("Close") } },
        )
    }
}

private fun Context.activeLanIpv4(): String? {
    val manager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val network = manager.activeNetwork ?: return null
    val capabilities = manager.getNetworkCapabilities(network) ?: return null
    if (!capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) return null
    return manager.getLinkProperties(network)?.linkAddresses?.asSequence()?.map { it.address }
        ?.filterIsInstance<java.net.Inet4Address>()
        ?.firstOrNull { it.isSiteLocalAddress && !it.isLoopbackAddress && !it.isAnyLocalAddress }
        ?.hostAddress
}

private fun decodeIncoming(encoded: ByteArray): Pair<String, String> {
    require(encoded.size >= 38) { "invalid_message" }
    val buffer = java.nio.ByteBuffer.wrap(encoded).order(java.nio.ByteOrder.BIG_ENDIAN)
    val peer = ByteArray(32).also { buffer.get(it) }
    val labelLength = buffer.short.toInt() and 0xffff
    require(labelLength <= 64 && buffer.remaining() >= labelLength + 4) { "invalid_message" }
    val label = ByteArray(labelLength).also { buffer.get(it) }.toString(Charsets.UTF_8)
    val textLength = buffer.int
    require(textLength in 0..clipcoreMaxTextBytes() && buffer.remaining() == textLength) { "invalid_message" }
    val text = ByteArray(textLength).also { buffer.get(it) }.toString(Charsets.UTF_8)
    peer.fill(0)
    return label to text
}

private fun clipcoreMaxTextBytes() = 65_484

@Composable
private fun StatusCard(identityState: IdentityState, paused: Boolean) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(if (paused) "Paused" else "Ready for a trusted device", style = MaterialTheme.typography.titleMedium)
            when (identityState) {
                IdentityState.Loading -> Text("Loading protected device identity…")
                is IdentityState.Ready -> Text("Android · identity ${identityState.metadata.shortFingerprint} · LAN text handoff available")
                is IdentityState.Unavailable -> Text(identityState.reason, color = MaterialTheme.colorScheme.error)
            }
            Text("Transport availability does not mean a device is trusted.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun DevicesScreen(padding: PaddingValues, identityState: IdentityState, context: ComponentActivity, paused: Boolean) {
    var devices by remember { mutableStateOf(emptyList<TrustedDeviceMetadata>()) }
    var revokeTarget by remember { mutableStateOf<TrustedDeviceMetadata?>(null) }
    var label by rememberSaveable { mutableStateOf("Windows device") }
    // QR payloads contain a short-lived invitation nonce and must not enter saved UI state.
    var invitationPayload by remember { mutableStateOf("") }
    var sas by remember { mutableStateOf<String?>(null) }
    var pairingBusy by rememberSaveable { mutableStateOf(false) }
    var pairingMessage by rememberSaveable { mutableStateOf<String?>(null) }
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    val trustStore = (identityState as? IdentityState.Ready)?.trustStore
    androidx.compose.runtime.LaunchedEffect(trustStore) {
        devices = trustStore?.let { runCatching { it.list() }.getOrDefault(emptyList()) } ?: emptyList()
    }
    Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("Devices", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
        Text("Trusted devices", style = MaterialTheme.typography.titleMedium)
        if (devices.isEmpty()) Text("No trusted devices yet.", style = MaterialTheme.typography.bodyLarge)
        devices.forEach { device ->
            Card {
                Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(device.label, style = MaterialTheme.typography.titleMedium)
                    Text(if (device.needsRepair) "Needs repair" else "Trusted · Offline", style = MaterialTheme.typography.bodyMedium)
                    Text("Fingerprint ${device.deviceId.joinToString("") { "%02x".format(it) }.take(12)} · Protocol ${device.minimumProtocol}", style = MaterialTheme.typography.bodySmall)
                    OutlinedButton(onClick = { revokeTarget = device }) { Text("Revoke trust") }
                }
            }
        }
        Card {
            Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Add a device", style = MaterialTheme.typography.titleSmall)
                Text("Scan the issuer’s current QR invitation. A nearby device is not trusted until both people compare and approve the same code.")
                OutlinedTextField(value = label, onValueChange = { label = it.take(64) }, label = { Text("Name this Windows device") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                Button(onClick = {
                    if (paused) {
                        pairingMessage = "Turn off Privacy Pause before pairing."
                    } else {
                        val scanOptions = GmsBarcodeScannerOptions.Builder()
                            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                            .enableAutoZoom()
                            .build()
                        GmsBarcodeScanning.getClient(context, scanOptions).startScan()
                            .addOnSuccessListener { barcode -> barcode.rawValue?.let { invitationPayload = it; pairingMessage = null } }
                            .addOnFailureListener { pairingMessage = "QR scan could not start. Paste the invitation payload below." }
                    }
                }, enabled = !pairingBusy, modifier = Modifier.fillMaxWidth()) { Text("Scan pairing QR") }
                Text("You can also paste the text encoded by the actual QR invitation.", style = MaterialTheme.typography.bodySmall)
                OutlinedTextField(value = invitationPayload, onValueChange = { invitationPayload = it.take(1024) }, label = { Text("Invitation payload") }, minLines = 2, modifier = Modifier.fillMaxWidth())
                Button(onClick = {
                    pairingBusy = true
                    pairingMessage = null
                    scope.launch {
                        val result = withContext(Dispatchers.IO) {
                            runCatching {
                                val bytes = invitationPayload.hexToBytesStrict()
                                val joined = try {
                                    NativeCore.nativeJoinPairing(bytes, label)
                                } finally {
                                    bytes.fill(0)
                                }
                                joined ?: error("Pairing could not start. Check the invitation and LAN connection.")
                            }.getOrElse { error -> error.message ?: "Pairing could not start." }
                        }
                        pairingBusy = false
                        invitationPayload = ""
                        if (result.contains('\t')) sas = result.substringBefore('\t') else pairingMessage = result
                        if (!result.contains('\t')) ActivityStore(context).record(ActivityKind.PAIRING_FAILED, label, "unknown", ActivityResult.FAILED)
                    }
                }, enabled = !paused && !pairingBusy && invitationPayload.isNotBlank() && label.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
                    Text(if (pairingBusy) "Connecting…" else "Verify issuer and compare code")
                }
                pairingMessage?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                if (pairingBusy) Text("Verifying the issuer and establishing an authenticated encrypted session…", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
    sas?.let { code ->
        AlertDialog(
            onDismissRequest = { pairingMessage = "Choose whether the codes match before leaving this step." },
            title = { Text("Compare this code") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Compare this code with the issuer on the other device.")
                    Text(code, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold, modifier = Modifier.semantics { contentDescription = "Pairing code $code" })
                    Text("Only continue when both screens show exactly the same code.", style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = {
                Button(enabled = !pairingBusy, onClick = {
                    pairingBusy = true
                    scope.launch {
                        val result = withContext(Dispatchers.IO) { runCatching { NativeCore.nativeConfirmPairing(true) ?: "pairing_incomplete" }.getOrElse { "pairing_incomplete" } }
                        pairingBusy = false
                        sas = null
                        if (result == "trusted") {
                            ActivityStore(context).record(ActivityKind.PAIRING_COMPLETED, label, "LAN Direct", ActivityResult.SUCCESS)
                            pairingMessage = "Device trusted. The issuer’s confirmation and acknowledgement were verified."
                            devices = runCatching { trustStore?.list().orEmpty() }.getOrDefault(emptyList())
                        } else {
                            pairingMessage = if (result == "pairing_needs_repair") "Pairing incomplete. Revoke stale trust and pair again with a fresh QR." else "Pairing incomplete. No device was trusted; retry with a fresh invitation."
                        }
                    }
                }) { Text(if (pairingBusy) "Verifying…" else "Codes match") }
            },
            dismissButton = {
                OutlinedButton(enabled = !pairingBusy, onClick = {
                    pairingBusy = true
                    scope.launch {
                        withContext(Dispatchers.IO) { NativeCore.nativeConfirmPairing(false) }
                        sas = null
                        pairingBusy = false
                        pairingMessage = "Pairing cancelled because the codes did not match. No trust was added."
                        ActivityStore(context).record(ActivityKind.PAIRING_FAILED, label, "unknown", ActivityResult.FAILED)
                    }
                }) { Text("Doesn’t match") }
            },
        )
    }
    revokeTarget?.let { device ->
        AlertDialog(
            onDismissRequest = { revokeTarget = null },
            title = { Text("Revoke ${device.label}?") },
            text = { Text("This device will no longer be able to send or receive protected text. Pair again to restore trust.") },
            confirmButton = {
                Button(onClick = {
                    scope.launch {
                        val revoked = withContext(Dispatchers.IO) { trustStore?.revoke(device) == true }
                        if (revoked) {
                            devices = trustStore?.let { runCatching { it.list() }.getOrDefault(emptyList()) }.orEmpty()
                            ActivityStore(context).record(ActivityKind.DEVICE_REVOKED, device.label, "unknown", ActivityResult.SUCCESS)
                        }
                        revokeTarget = null
                    }
                }) { Text("Revoke trust") }
            },
            dismissButton = { OutlinedButton(onClick = { revokeTarget = null }) { Text("Cancel") } },
        )
    }
}

private fun String.hexToBytesStrict(): ByteArray {
    require(length in 2..1024 && length % 2 == 0 && all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) { "invalid_pairing_input" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

@Composable
private fun ActivityScreen(padding: PaddingValues, context: Context) {
    var events by remember { mutableStateOf(ActivityStore(context).list()) }
    androidx.compose.runtime.LaunchedEffect(Unit) { events = ActivityStore(context).list() }
    Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Activity", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
        Text("Activity contains transfer metadata only. Content history is off.", style = MaterialTheme.typography.bodyMedium)
        HorizontalDivider()
        if (events.isEmpty()) Text("No activity yet.", color = MaterialTheme.colorScheme.onSurfaceVariant)
        events.forEach { event ->
            Card {
                Column(Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(event.kind.label, style = MaterialTheme.typography.titleSmall)
                    Text(event.deviceLabel.ifBlank { "Device" }, style = MaterialTheme.typography.bodyMedium)
                    Text("${event.route} · ${event.result.value} · ${android.text.format.DateUtils.getRelativeTimeSpanString(event.timestampMillis)}", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
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
                        Column(Modifier.weight(1f)) { Text("Privacy Pause"); Text("Blocks outgoing sends, pairing, and incoming text delivery while enabled.", style = MaterialTheme.typography.bodySmall) }
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
            Text("LAN text handoff is available with explicit pairing and a foreground receiver. Background receiving and auto-sync are off.", style = MaterialTheme.typography.bodySmall)
        } else {
            OutlinedButton(onClick = { section = "Settings" }, modifier = Modifier.fillMaxWidth()) { Text("Back to Settings") }
            Text("Help", style = MaterialTheme.typography.titleMedium)
            Text("Android reads clipboard data only while this app is focused. Use Read Clipboard after opening ClipBridge; no background polling is performed.")
            Text("Scan the current Windows pairing QR, compare the code on both devices, then approve only when it matches. LAN uses a manual endpoint and a fresh authenticated encrypted session for each text handoff.")
            HorizontalDivider()
            Text("Diagnostics", style = MaterialTheme.typography.titleMedium)
            val identity = when (identityState) {
                IdentityState.Loading -> "loading"
                is IdentityState.Ready -> "protected_identity_ready"
                is IdentityState.Unavailable -> "protected_identity_unavailable"
            }
            val trustStatus = if (identityState is IdentityState.Ready) "ready" else "unavailable"
            val report = serializeDiagnostics(
                SafeDiagnostics(
                    appVersion = runCatching { context.packageManager.getPackageInfo(context.packageName, 0).versionName }.getOrNull() ?: "unknown",
                    androidApi = Build.VERSION.SDK_INT,
                    identityState = identity.removePrefix("protected_identity_"),
                    trustStoreState = trustStatus,
                    listenerState = if (context.getSharedPreferences("runtime", Context.MODE_PRIVATE).getBoolean("receiver_active", false)) "active" else "inactive",
                    privacyPaused = paused,
                    lastErrorCode = if (identityState is IdentityState.Unavailable) "secure_store_unavailable"
                        else context.getSharedPreferences("runtime", Context.MODE_PRIVATE).getString("last_error", "none") ?: "none",
                ),
            )
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

