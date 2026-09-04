package com.example.dpibypass

object PacketUtils {

    const val IP_ICMP = 1
    const val IP_TCP = 6
    const val IP_UDP = 17

    fun readShort(buf: ByteArray, off: Int): Int {
        return ((buf[off].toInt() and 0xFF) shl 8) or
            (buf[off + 1].toInt() and 0xFF)
    }

    fun readInt(buf: ByteArray, off: Int): Int {
        return ((buf[off].toInt() and 0xFF) shl 24) or
            ((buf[off + 1].toInt() and 0xFF) shl 16) or
            ((buf[off + 2].toInt() and 0xFF) shl 8) or
            (buf[off + 3].toInt() and 0xFF)
    }

    fun readIntUnsigned(buf: ByteArray, off: Int): Long {
        return readInt(buf, off).toLong() and 0xFFFFFFFFL
    }

    fun writeShort(buf: ByteArray, off: Int, value: Int) {
        buf[off] = ((value shr 8) and 0xFF).toByte()
        buf[off + 1] = (value and 0xFF).toByte()
    }

    fun writeInt(buf: ByteArray, off: Int, value: Int) {
        buf[off] = ((value shr 24) and 0xFF).toByte()
        buf[off + 1] = ((value shr 16) and 0xFF).toByte()
        buf[off + 2] = ((value shr 8) and 0xFF).toByte()
        buf[off + 3] = (value and 0xFF).toByte()
    }

    fun intToIp(ip: Int): String {
        return "${(ip ushr 24) and 0xFF}." +
            "${(ip ushr 16) and 0xFF}." +
            "${(ip ushr 8) and 0xFF}." +
            "${ip and 0xFF}"
    }

    fun ipToInt(ip: String): Int {
        val parts = ip.split(".")
        if (parts.size != 4) return 0

        var result = 0
        for (part in parts) {
            val value = part.toIntOrNull() ?: return 0
            result = (result shl 8) or (value and 0xFF)
        }
        return result
    }

    fun seqGreater(a: Long, b: Long): Boolean {
        val diff = (a - b) and 0xFFFFFFFFL
        return diff != 0L && diff < 0x80000000L
    }

    fun seqLess(a: Long, b: Long): Boolean {
        return seqGreater(b, a)
    }

    fun addSeq(seq: Long, add: Int): Long {
        return (seq + add.toLong()) and 0xFFFFFFFFL
    }

    private fun sumWords(data: ByteArray, offset: Int, length: Int, initial: Long): Long {
        var sum = initial
        var i = offset
        val end = offset + length

        while (i + 1 < end) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or
                (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }

        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }

        return sum
    }

    private fun foldChecksum(sum: Long): Int {
        var s = sum
        while ((s ushr 16) != 0L) {
            s = (s and 0xFFFF) + (s ushr 16)
        }
        return ((s.inv()) and 0xFFFF).toInt()
    }

    fun ipChecksum(data: ByteArray, offset: Int, length: Int): Int {
        val sum = sumWords(data, offset, length, 0L)
        return foldChecksum(sum)
    }

    fun tcpUdpChecksum(
        srcIp: Int,
        dstIp: Int,
        protocol: Int,
        segment: ByteArray,
        length: Int
    ): Int {
        val src = srcIp.toLong() and 0xFFFFFFFFL
        val dst = dstIp.toLong() and 0xFFFFFFFFL

        var sum = 0L
        sum += (src ushr 16) and 0xFFFF
        sum += src and 0xFFFF
        sum += (dst ushr 16) and 0xFFFF
        sum += dst and 0xFFFF
        sum += protocol.toLong()
        sum += length.toLong()

        sum = sumWords(segment, 0, length, sum)

        return foldChecksum(sum)
    }

    fun buildIpPacket(
        protocol: Int,
        srcIp: Int,
        dstIp: Int,
        payload: ByteArray,
        payloadOffset: Int = 0,
        payloadLength: Int = payload.size - payloadOffset
    ): ByteArray {
        val totalLength = 20 + payloadLength
        val packet = ByteArray(totalLength)

        packet[0] = 0x45
        packet[1] = 0

        writeShort(packet, 2, totalLength)
        writeShort(packet, 4, 0)
        writeShort(packet, 6, 0x4000)

        packet[8] = 64
        packet[9] = protocol.toByte()

        writeInt(packet, 12, srcIp)
        writeInt(packet, 16, dstIp)

        val checksum = ipChecksum(packet, 0, 20)
        writeShort(packet, 10, checksum)

        if (payloadLength > 0) {
            System.arraycopy(payload, payloadOffset, packet, 20, payloadLength)
        }

        return packet
    }

    fun buildTcpSegment(
        srcIp: Int,
        dstIp: Int,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        window: Int,
        payload: ByteArray? = null,
        payloadOffset: Int = 0,
        payloadLength: Int = 0,
        includeMss: Boolean = false
    ): ByteArray {
        val headerLength = if (includeMss) 24 else 20
        val totalLength = headerLength + payloadLength
        val segment = ByteArray(totalLength)

        writeShort(segment, 0, srcPort)
        writeShort(segment, 2, dstPort)

        writeInt(segment, 4, seq.toInt())
        writeInt(segment, 8, ack.toInt())

        segment[12] = (((headerLength / 4) shl 4)).toByte()
        segment[13] = flags.toByte()

        writeShort(segment, 14, window and 0xFFFF)
        writeShort(segment, 16, 0)
        writeShort(segment, 18, 0)

        if (includeMss) {
            segment[20] = 2
            segment[21] = 4
            writeShort(segment, 22, 1460)
        }

        if (payload != null && payloadLength > 0) {
            System.arraycopy(payload, payloadOffset, segment, headerLength, payloadLength)
        }

        val checksum = tcpUdpChecksum(srcIp, dstIp, IP_TCP, segment, totalLength)
        writeShort(segment, 16, checksum)

        return segment
    }

    fun buildUdpSegment(
        srcIp: Int,
        dstIp: Int,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val totalLength = 8 + payload.size
        val segment = ByteArray(totalLength)

        writeShort(segment, 0, srcPort)
        writeShort(segment, 2, dstPort)
        writeShort(segment, 4, totalLength)
        writeShort(segment, 6, 0)

        System.arraycopy(payload, 0, segment, 8, payload.size)

        var checksum = tcpUdpChecksum(srcIp, dstIp, IP_UDP, segment, totalLength)
        if (checksum == 0) checksum = 0xFFFF

        writeShort(segment, 6, checksum)

        return segment
    }

    fun buildIcmpPortUnreachable(
        originalPacket: ByteArray,
        originalLength: Int,
        srcIp: Int,
        dstIp: Int
    ): ByteArray {
        val copyLength = minOf(originalLength, 28)
        val icmpLength = 8 + copyLength
        val icmp = ByteArray(icmpLength)

        icmp[0] = 3
        icmp[1] = 3

        System.arraycopy(originalPacket, 0, icmp, 8, copyLength)

        val checksum = ipChecksum(icmp, 0, icmpLength)
        writeShort(icmp, 2, checksum)

        return buildIpPacket(IP_ICMP, srcIp, dstIp, icmp)
    }
}
