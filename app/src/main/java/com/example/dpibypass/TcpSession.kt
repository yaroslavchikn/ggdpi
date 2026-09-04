package com.example.dpibypass

import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

class TcpSession(
    private val service: DpiVpnService,
    val clientIp: Int,
    val clientPort: Int,
    val serverIp: Int,
    val serverPort: Int
) {

    companion object {
        const val STATE_SYN_RECEIVED = 0
        const val STATE_ESTABLISHED = 1
        const val STATE_CLOSED = 2

        const val FLAG_FIN = 0x01
        const val FLAG_SYN = 0x02
        const val FLAG_RST = 0x04
        const val FLAG_PSH = 0x08
        const val FLAG_ACK = 0x10

        private const val MAX_SEGMENT = 1460
    }

    @Volatile
    private var closed = false

    var state = STATE_SYN_RECEIVED
    var lastActive = System.currentTimeMillis()

    private var clientNextSeq = 0L

    private val initialServerSeq = System.nanoTime() and 0xFFFFFFFFL
    private var serverNextSeq = initialServerSeq
    private var lastAckFromClient = initialServerSeq

    private var clientWindow = 65535

    private var upstream: Socket? = null
    private var upstreamConnected = false

    private var firstData = true
    private var finSent = false

    private val pending = ByteArrayOutputStream()
    private val lock = Object()
    private val upstreamLock = Object()

    fun key(): String {
        return "$clientPort:$serverIp:$serverPort"
    }

    fun isClosed(): Boolean {
        return closed
    }

    fun onTcpPacket(
        seq: Long,
        ack: Long,
        flags: Int,
        window: Int,
        packet: ByteArray,
        payloadOffset: Int,
        payloadLen: Int
    ) {
        lastActive = System.currentTimeMillis()

        synchronized(lock) {
            clientWindow = window and 0xFFFF

            if (state == STATE_ESTABLISHED && (flags and FLAG_ACK) != 0) {
                if (PacketUtils.seqGreater(ack, lastAckFromClient) &&
                    !PacketUtils.seqGreater(ack, serverNextSeq)
                ) {
                    lastAckFromClient = ack
                    lock.notifyAll()
                }
            }
        }

        if ((flags and FLAG_RST) != 0) {
            close()
            return
        }

        if ((flags and FLAG_SYN) != 0 && (flags and FLAG_ACK) == 0) {
            if (state == STATE_SYN_RECEIVED) {
                clientNextSeq = PacketUtils.addSeq(seq, 1)
                sendSynAck()
            }
            return
        }

        if ((flags and FLAG_ACK) != 0 && state == STATE_SYN_RECEIVED) {
            val expectedAck = PacketUtils.addSeq(initialServerSeq, 1)
            if (ack == expectedAck) {
                state = STATE_ESTABLISHED
                serverNextSeq = expectedAck

                synchronized(lock) {
                    lastAckFromClient = expectedAck
                    lock.notifyAll()
                }

                openUpstream()
            }
        }

        if (state == STATE_ESTABLISHED && payloadLen > 0) {
            if (seq == clientNextSeq) {
                clientNextSeq = PacketUtils.addSeq(clientNextSeq, payloadLen)
                sendAck()
                forwardToUpstream(packet, payloadOffset, payloadLen)
            } else {
                sendAck()
            }
        }

        if ((flags and FLAG_FIN) != 0) {
            val expectedFinSeq = PacketUtils.addSeq(seq, payloadLen)
            if (expectedFinSeq == clientNextSeq) {
                clientNextSeq = PacketUtils.addSeq(clientNextSeq, 1)
                sendAck()
                shutdownUpstreamOutput()
            }
        }
    }

    private fun sendSynAck() {
        val segment = PacketUtils.buildTcpSegment(
            srcIp = serverIp,
            dstIp = clientIp,
            srcPort = serverPort,
            dstPort = clientPort,
            seq = initialServerSeq,
            ack = clientNextSeq,
            flags = FLAG_SYN or FLAG_ACK,
            window = 65535,
            payload = null,
            payloadOffset = 0,
            payloadLength = 0,
            includeMss = true
        )

        val ipPacket = PacketUtils.buildIpPacket(
            protocol = PacketUtils.IP_TCP,
            srcIp = serverIp,
            dstIp = clientIp,
            payload = segment
        )

        service.writePacket(ipPacket)
    }

    private fun sendAck() {
        val seq: Long
        val ack: Long

        synchronized(lock) {
            seq = serverNextSeq
            ack = clientNextSeq
        }

        val segment = PacketUtils.buildTcpSegment(
            srcIp = serverIp,
            dstIp = clientIp,
            srcPort = serverPort,
            dstPort = clientPort,
            seq = seq,
            ack = ack,
            flags = FLAG_ACK,
            window = 65535
        )

        val ipPacket = PacketUtils.buildIpPacket(
            protocol = PacketUtils.IP_TCP,
            srcIp = serverIp,
            dstIp = clientIp,
            payload = segment
        )

        service.writePacket(ipPacket)
    }

    private fun sendRst() {
        val seq: Long
        val ack: Long

        synchronized(lock) {
            seq = serverNextSeq
            ack = clientNextSeq
        }

        val segment = PacketUtils.buildTcpSegment(
            srcIp = serverIp,
            dstIp = clientIp,
            srcPort = serverPort,
            dstPort = clientPort,
            seq = seq,
            ack = ack,
            flags = FLAG_RST or FLAG_ACK,
            window = 0
        )

        val ipPacket = PacketUtils.buildIpPacket(
            protocol = PacketUtils.IP_TCP,
            srcIp = serverIp,
            dstIp = clientIp,
            payload = segment
        )

        service.writePacket(ipPacket)
    }

    private fun openUpstream() {
        service.executeTask {
            if (closed) return@executeTask

            try {
                val socket = Socket()

                service.protect(socket)

                socket.tcpNoDelay = true
                socket.sendBufferSize = 2048
                socket.soTimeout = 120_000

                socket.connect(
                    InetSocketAddress(PacketUtils.intToIp(serverIp), serverPort),
                    8000
                )

                var buffered: ByteArray? = null

                synchronized(lock) {
                    if (closed) {
                        socket.close()
                        return@executeTask
                    }

                    upstream = socket
                    upstreamConnected = true

                    buffered = pending.toByteArray()
                    pending.reset()

                    lock.notifyAll()
                }

                val data = buffered
                if (data != null && data.isNotEmpty()) {
                    writeUpstream(data, 0, data.size)
                }

                service.executeTask {
                    readUpstream(socket)
                }

            } catch (_: Exception) {
                sendRst()
                close()
            }
        }
    }

    private fun forwardToUpstream(data: ByteArray, offset: Int, length: Int) {
        if (closed) return

        synchronized(lock) {
            if (!upstreamConnected) {
                pending.write(data, offset, length)
                return
            }
        }

        try {
            writeUpstream(data, offset, length)
        } catch (_: Exception) {
            close()
        }
    }

    private fun writeUpstream(data: ByteArray, offset: Int, length: Int) {
        val socket = upstream ?: return

        synchronized(upstreamLock) {
            val out = socket.getOutputStream()

            if (firstData) {
                firstData = false
                writeFragmented(out, data, offset, length)
            } else {
                out.write(data, offset, length)
                out.flush()
            }
        }
    }

    private fun writeFragmented(
        out: OutputStream,
        data: ByteArray,
        offset: Int,
        length: Int
    ) {
        var pos = offset
        val end = offset + length

        val pieces = intArrayOf(1, 2, 3, 5, 8, 13, 21, 34)

        for (size in pieces) {
            if (pos >= end) break

            val chunk = minOf(size, end - pos)
            out.write(data, pos, chunk)
            out.flush()

            try {
                Thread.sleep(2)
            } catch (_: InterruptedException) {
                // ignore
            }

            pos += chunk
        }

        if (pos < end) {
            out.write(data, pos, end - pos)
            out.flush()
        }
    }

    private fun readUpstream(socket: Socket) {
        try {
            val input = socket.getInputStream()
            val buffer = ByteArray(8192)

            while (!closed) {
                val n = input.read(buffer)
                if (n < 0) break

                sendDataToClient(buffer, 0, n)
            }

            sendFin()
        } catch (_: Exception) {
            close()
        }
    }

    private fun sendDataToClient(data: ByteArray, offset: Int, length: Int) {
        var pos = offset
        val end = offset + length

        while (pos < end && !closed) {
            var chunk = 0
            var seq: Long
            var ack: Long

            synchronized(lock) {
                while (!closed) {
                    val outstanding = (serverNextSeq - lastAckFromClient) and 0xFFFFFFFFL
                    val available = clientWindow.toLong() - outstanding

                    if (available > 0) {
                        chunk = minOf(
                            MAX_SEGMENT.toLong(),
                            (end - pos).toLong(),
                            available
                        ).toInt()
                        break
                    }

                    try {
                        lock.wait(100)
                    } catch (_: InterruptedException) {
                        break
                    }
                }

                seq = serverNextSeq
                ack = clientNextSeq
            }

            if (closed || chunk <= 0) break

            val segment = PacketUtils.buildTcpSegment(
                srcIp = serverIp,
                dstIp = clientIp,
                srcPort = serverPort,
                dstPort = clientPort,
                seq = seq,
                ack = ack,
                flags = FLAG_ACK or FLAG_PSH,
                window = 65535,
                payload = data,
                payloadOffset = pos,
                payloadLength = chunk,
                includeMss = false
            )

            val ipPacket = PacketUtils.buildIpPacket(
                protocol = PacketUtils.IP_TCP,
                srcIp = serverIp,
                dstIp = clientIp,
                payload = segment
            )

            service.writePacket(ipPacket)

            synchronized(lock) {
                serverNextSeq = PacketUtils.addSeq(serverNextSeq, chunk)
            }

            pos += chunk
        }
    }

    private fun sendFin() {
        synchronized(lock) {
            if (closed || finSent) return

            var attempts = 0

            while (!closed && attempts < 50) {
                val outstanding = (serverNextSeq - lastAckFromClient) and 0xFFFFFFFFL
                if (outstanding == 0L) break

                try {
                    lock.wait(100)
                } catch (_: InterruptedException) {
                    break
                }

                attempts++
            }

            if (closed) return

            val segment = PacketUtils.buildTcpSegment(
                srcIp = serverIp,
                dstIp = clientIp,
                srcPort = serverPort,
                dstPort = clientPort,
                seq = serverNextSeq,
                ack = clientNextSeq,
                flags = FLAG_FIN or FLAG_ACK,
                window = 65535
            )

            val ipPacket = PacketUtils.buildIpPacket(
                protocol = PacketUtils.IP_TCP,
                srcIp = serverIp,
                dstIp = clientIp,
                payload = segment
            )

            service.writePacket(ipPacket)

            serverNextSeq = PacketUtils.addSeq(serverNextSeq, 1)
            finSent = true
        }
    }

    private fun shutdownUpstreamOutput() {
        try {
            upstream?.shutdownOutput()
        } catch (_: Exception) {
            // ignore
        }
    }

    fun close() {
        if (closed) return

        closed = true
        state = STATE_CLOSED

        runCatching { upstream?.close() }

        synchronized(lock) {
            lock.notifyAll()
        }

        service.removeSession(this)
    }
}
