package com.example.dpibypass

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class DpiVpnService : VpnService() {

    companion object {
        const val ACTION_STOP = "com.example.dpibypass.ACTION_STOP"

        private const val CHANNEL_ID = "dpi_bypass_vpn_v2"
        private const val NOTIFICATION_ID = 2

        private const val VPN_ADDRESS_V4 = "10.10.10.1"
        private const val VPN_ADDRESS_V6 = "fd00:1::1"
    }

    private var pfd: ParcelFileDescriptor? = null
    private var input: FileInputStream? = null
    private var output: FileOutputStream? = null

    @Volatile
    private var running = false

    private var tunThread: Thread? = null
    private var cleanerThread: Thread? = null

    private var executor: ExecutorService = Executors.newCachedThreadPool()

    private val sessions = ConcurrentHashMap<String, TcpSession>()
    private val dnsResponder = DnsResponder(DohResolver())

    private val writeLock = Object()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            stopSelf()
            return START_NOT_STICKY
        }

        createNotificationChannel()

        val stopIntent = Intent(this, DpiVpnService::class.java).apply {
            action = ACTION_STOP
        }

        val stopPendingIntent = PendingIntent.getService(
            this,
            0,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("DPI Bypass v2")
            .setContentText("Перехват TCP + фрагментация + DoH")
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setOngoing(true)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Стоп",
                stopPendingIntent
            )
            .build()

        startForeground(NOTIFICATION_ID, notification)

        startVpn()

        return START_STICKY
    }

    private fun createNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "VPN",
                NotificationManager.IMPORTANCE_LOW
            )
            manager.createNotificationChannel(channel)
        }
    }

    private fun startVpn() {
        if (running) return

        try {
            if (executor.isShutdown) {
                executor = Executors.newCachedThreadPool()
            }

            val builder = Builder()
                .setSession("DPI Bypass v2")
                .setMtu(1500)
                .addAddress(VPN_ADDRESS_V4, 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(VPN_ADDRESS_V4)

            runCatching {
                builder.addAddress(VPN_ADDRESS_V6, 128)
                builder.addRoute("::", 0)
            }

            val targetPackages = listOf(
                "com.google.android.youtube",
                "com.google.android.apps.youtube.music",
                "com.android.chrome",
                "com.android.vending"
            )

            targetPackages.forEach { pkg ->
                runCatching {
                    builder.addAllowedApplication(pkg)
                }
            }

            pfd = builder.establish() ?: run {
                stopVpn()
                stopSelf()
                return
            }

            input = FileInputStream(pfd!!.fileDescriptor)
            output = FileOutputStream(pfd!!.fileDescriptor)

            running = true

            tunThread = Thread {
                tunLoop()
            }.apply {
                start()
            }

            cleanerThread = Thread {
                cleanerLoop()
            }.apply {
                start()
            }

        } catch (e: Exception) {
            e.printStackTrace()
            stopVpn()
            stopSelf()
        }
    }

    private fun tunLoop() {
        val buffer = ByteArray(32768)

        try {
            while (running) {
                val n = input?.read(buffer) ?: -1
                if (n < 20) {
                    if (n < 0) break
                    continue
                }

                val version = (buffer[0].toInt() ushr 4) and 0xF

                if (version == 4) {
                    handleIpv4(buffer, n)
                } else {
                    // IPv6 dropped intentionally.
                }
            }
        } catch (_: Exception) {
            // ignore
        }
    }

    private fun handleIpv4(packet: ByteArray, length: Int) {
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl) return

        val totalLength = PacketUtils.readShort(packet, 2)
        val actualLength = if (totalLength in ihl..length) totalLength else length

        val protocol = packet[9].toInt() and 0xFF
        val srcIp = PacketUtils.readInt(packet, 12)
        val dstIp = PacketUtils.readInt(packet, 16)

        when (protocol) {
            PacketUtils.IP_TCP -> handleTcp(packet, actualLength, ihl, srcIp, dstIp)
            PacketUtils.IP_UDP -> handleUdp(packet, actualLength, ihl, srcIp, dstIp)
            else -> {
                // drop
            }
        }
    }

    private fun handleTcp(
        packet: ByteArray,
        length: Int,
        ipHeaderLength: Int,
        srcIp: Int,
        dstIp: Int
    ) {
        val tcpOffset = ipHeaderLength
        if (length < tcpOffset + 20) return

        val srcPort = PacketUtils.readShort(packet, tcpOffset)
        val dstPort = PacketUtils.readShort(packet, tcpOffset + 2)

        val seq = PacketUtils.readIntUnsigned(packet, tcpOffset + 4)
        val ack = PacketUtils.readIntUnsigned(packet, tcpOffset + 8)

        val dataOffset = ((packet[tcpOffset + 12].toInt() ushr 4) and 0xF) * 4
        if (dataOffset < 20) return

        val flags = packet[tcpOffset + 13].toInt() and 0xFF
        val window = PacketUtils.readShort(packet, tcpOffset + 14)

        val payloadLength = length - tcpOffset - dataOffset
        if (payloadLength < 0) return

        val payloadOffset = tcpOffset + dataOffset

        val key = "$srcPort:$dstIp:$dstPort"

        var session = sessions[key]

        if (session == null) {
            if ((flags and TcpSession.FLAG_SYN) != 0 &&
                (flags and TcpSession.FLAG_ACK) == 0
            ) {
                session = TcpSession(
                    service = this,
                    clientIp = srcIp,
                    clientPort = srcPort,
                    serverIp = dstIp,
                    serverPort = dstPort
                )

                sessions[key] = session
                session.onTcpPacket(seq, ack, flags, window, packet, payloadOffset, payloadLength)
            } else {
                // No session and not a SYN: drop.
            }
        } else {
            session.onTcpPacket(seq, ack, flags, window, packet, payloadOffset, payloadLength)

            if (session.isClosed()) {
                sessions.remove(key)
            }
        }
    }

    private fun handleUdp(
        packet: ByteArray,
        length: Int,
        ipHeaderLength: Int,
        srcIp: Int,
        dstIp: Int
    ) {
        val udpOffset = ipHeaderLength
        if (length < udpOffset + 8) return

        val srcPort = PacketUtils.readShort(packet, udpOffset)
        val dstPort = PacketUtils.readShort(packet, udpOffset + 2)
        val udpLength = PacketUtils.readShort(packet, udpOffset + 4)

        if (udpLength < 8) return

        val payloadLength = minOf(udpLength - 8, length - udpOffset - 8)
        if (payloadLength < 0) return

        val payloadOffset = udpOffset + 8

        if (dstPort == 53) {
            val dnsResponse = dnsResponder.respond(packet, payloadOffset, payloadLength)

            if (dnsResponse != null) {
                val udpSegment = PacketUtils.buildUdpSegment(
                    srcIp = dstIp,
                    dstIp = srcIp,
                    srcPort = dstPort,
                    dstPort = srcPort,
                    payload = dnsResponse
                )

                val ipPacket = PacketUtils.buildIpPacket(
                    protocol = PacketUtils.IP_UDP,
                    srcIp = dstIp,
                    dstIp = srcIp,
                    payload = udpSegment
                )

                writePacket(ipPacket)
            }
        } else {
            // Drop all non-DNS UDP and force TCP fallback.
            val icmp = PacketUtils.buildIcmpPortUnreachable(
                originalPacket = packet,
                originalLength = length,
                srcIp = dstIp,
                dstIp = srcIp
            )

            writePacket(icmp)
        }
    }

    fun writePacket(packet: ByteArray) {
        synchronized(writeLock) {
            try {
                output?.write(packet)
            } catch (_: Exception) {
                // ignore
            }
        }
    }

    fun executeTask(task: () -> Unit) {
        if (executor.isShutdown) return

        try {
            executor.submit {
                task()
            }
        } catch (_: Exception) {
            // ignore
        }
    }

    fun removeSession(session: TcpSession) {
        sessions.remove(session.key())
    }

    private fun cleanerLoop() {
        while (running) {
            try {
                Thread.sleep(30_000)

                val now = System.currentTimeMillis()

                sessions.values.forEach { session ->
                    if (session.isClosed() || now - session.lastActive > 180_000) {
                        session.close()
                    }
                }

            } catch (_: InterruptedException) {
                break
            } catch (_: Exception) {
                // ignore
            }
        }
    }

    private fun stopVpn() {
        running = false

        sessions.values.forEach { session ->
            runCatching { session.close() }
        }
        sessions.clear()

        runCatching { tunThread?.interrupt() }
        runCatching { cleanerThread?.interrupt() }

        tunThread = null
        cleanerThread = null

        runCatching { input?.close() }
        runCatching { output?.close() }
        runCatching { pfd?.close() }

        input = null
        output = null
        pfd = null

        runCatching {
            if (!executor.isShutdown) {
                executor.shutdownNow()
            }
        }

        stopForeground(true)
    }

    override fun onRevoke() {
        stopVpn()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
