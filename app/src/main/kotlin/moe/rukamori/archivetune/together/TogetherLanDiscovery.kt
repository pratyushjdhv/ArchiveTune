/*
 * ArchiveTune (2026)
 * © Rukamori — github.com/rukamori
 * GPL-3.0 License | Contributors: see git history
 * Do not remove or alter this notice. - Per GPL-3.0 Section 4 & Section 5
 */

package moe.rukamori.archivetune.together

import android.content.Context
import android.net.wifi.WifiManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.security.SecureRandom

/**
 * Lets a guest join a LAN room with a short numeric code instead of a full link.
 *
 * The host listens on a fixed UDP port. The guest sends "who has code X?" to the network
 * broadcast addresses, to its gateway (which is the host when the guest is on the host's hotspot)
 * and to every address in its /24 subnet, so it still works on networks that drop broadcasts.
 * The host answers with the full join link; the guest uses the address the answer came from as
 * the host address, so a wrong local-IP guess on the host does not matter.
 */
object TogetherLanDiscovery {
    const val DiscoveryPort = 42118
    private const val RequestPrefix = "ARCHIVETUNE_TOGETHER_DISCOVER_V1 "
    private const val ResponsePrefix = "ARCHIVETUNE_TOGETHER_HOST_V1 "
    private val CodeRegex = Regex("^\\d{4,6}$")

    fun isCode(raw: String): Boolean = CodeRegex.matches(raw.trim())

    fun generateCode(): String = (100000 + SecureRandom().nextInt(900000)).toString()

    class Responder(
        private val context: Context,
        private val code: String,
        private val joinLink: String,
    ) {
        private var socket: DatagramSocket? = null
        private var job: Job? = null
        private var multicastLock: WifiManager.MulticastLock? = null

        fun start(scope: CoroutineScope) {
            if (job != null) return
            multicastLock =
                runCatching {
                    (context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager)
                        ?.createMulticastLock("ArchiveTuneTogetherDiscovery")
                        ?.apply {
                            setReferenceCounted(false)
                            acquire()
                        }
                }.getOrNull()

            val s =
                runCatching {
                    DatagramSocket(null).apply {
                        reuseAddress = true
                        broadcast = true
                        bind(InetSocketAddress(DiscoveryPort))
                    }
                }.getOrElse {
                    Timber.tag("Together").w(it, "LAN discovery responder could not bind")
                    releaseLock()
                    return
                }
            socket = s

            job =
                scope.launch(Dispatchers.IO) {
                    val buffer = ByteArray(512)
                    while (isActive && !s.isClosed) {
                        val packet = DatagramPacket(buffer, buffer.size)
                        try {
                            s.receive(packet)
                        } catch (_: Exception) {
                            if (s.isClosed) break else continue
                        }
                        val text = String(packet.data, packet.offset, packet.length, Charsets.UTF_8).trim()
                        if (!text.startsWith(RequestPrefix)) continue
                        if (text.removePrefix(RequestPrefix).trim() != code) continue
                        val reply = (ResponsePrefix + code + " " + joinLink).toByteArray(Charsets.UTF_8)
                        runCatching {
                            s.send(DatagramPacket(reply, reply.size, packet.address, packet.port))
                        }
                    }
                }
        }

        fun stop() {
            job?.cancel()
            job = null
            runCatching { socket?.close() }
            socket = null
            releaseLock()
        }

        private fun releaseLock() {
            runCatching { multicastLock?.takeIf { it.isHeld }?.release() }
            multicastLock = null
        }
    }

    /** Finds the host announcing [code] on the local network, or returns null after [timeoutMs]. */
    suspend fun discover(
        context: Context,
        code: String,
        timeoutMs: Long = 8000L,
    ): TogetherJoinInfo? =
        withContext(Dispatchers.IO) {
            val wanted = code.trim()
            val request = (RequestPrefix + wanted).toByteArray(Charsets.UTF_8)
            val socket =
                runCatching {
                    DatagramSocket().apply {
                        broadcast = true
                        soTimeout = 400
                    }
                }.getOrElse { return@withContext null }

            try {
                val deadline = System.currentTimeMillis() + timeoutMs
                var round = 0
                val buffer = ByteArray(2048)
                while (System.currentTimeMillis() < deadline) {
                    val targets = discoveryTargets(context, includeSubnetSweep = round % 3 == 0)
                    targets.forEach { address ->
                        runCatching { socket.send(DatagramPacket(request, request.size, address, DiscoveryPort)) }
                    }
                    round++

                    val listenUntil = minOf(deadline, System.currentTimeMillis() + 1200L)
                    while (System.currentTimeMillis() < listenUntil) {
                        val packet = DatagramPacket(buffer, buffer.size)
                        try {
                            socket.receive(packet)
                        } catch (_: SocketTimeoutException) {
                            continue
                        }
                        val text = String(packet.data, packet.offset, packet.length, Charsets.UTF_8).trim()
                        if (!text.startsWith(ResponsePrefix)) continue
                        val rest = text.removePrefix(ResponsePrefix).trim()
                        val replyCode = rest.substringBefore(' ')
                        if (replyCode != wanted) continue
                        val info = TogetherLink.decode(rest.substringAfter(' ')) ?: continue
                        val hostAddress = packet.address?.hostAddress?.takeIf { it.isNotBlank() } ?: info.host
                        return@withContext info.copy(host = hostAddress)
                    }
                }
                null
            } catch (t: Throwable) {
                Timber.tag("Together").w(t, "LAN discovery failed")
                null
            } finally {
                runCatching { socket.close() }
            }
        }

    private fun discoveryTargets(
        context: Context,
        includeSubnetSweep: Boolean,
    ): Set<InetAddress> {
        val targets = LinkedHashSet<InetAddress>()
        runCatching { targets += InetAddress.getByName("255.255.255.255") }

        @Suppress("DEPRECATION")
        runCatching {
            val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            val gateway = wifi?.dhcpInfo?.gateway ?: 0
            if (gateway != 0) targets += intToInet4(gateway)
        }

        runCatching {
            NetworkInterface
                .getNetworkInterfaces()
                .toList()
                .filter { it.isUp && !it.isLoopback }
                .forEach { nif ->
                    nif.interfaceAddresses.forEach { ia ->
                        val address = ia.address as? Inet4Address ?: return@forEach
                        // Only local networks (Wi-Fi, hotspot); never the mobile data interface.
                        if (!address.isSiteLocalAddress) return@forEach
                        ia.broadcast?.let { targets += it }
                        if (includeSubnetSweep && ia.networkPrefixLength >= 24) {
                            val bytes = address.address
                            for (last in 1..254) {
                                if (last == (bytes[3].toInt() and 0xFF)) continue
                                targets +=
                                    InetAddress.getByAddress(
                                        byteArrayOf(bytes[0], bytes[1], bytes[2], last.toByte()),
                                    )
                            }
                        }
                    }
                }
        }
        return targets
    }

    private fun intToInet4(value: Int): InetAddress =
        InetAddress.getByAddress(
            byteArrayOf(
                (value and 0xFF).toByte(),
                (value shr 8 and 0xFF).toByte(),
                (value shr 16 and 0xFF).toByte(),
                (value shr 24 and 0xFF).toByte(),
            ),
        )
}
