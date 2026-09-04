package com.example.dpibypass

import java.io.ByteArrayOutputStream

class DnsResponder(private val resolver: DohResolver) {

    private class Question(
        val name: String,
        val type: Int,
        val end: Int
    )

    fun respond(query: ByteArray, offset: Int, length: Int): ByteArray? {
        if (length < 12) return null

        val q = ByteArray(length)
        System.arraycopy(query, offset, q, 0, length)

        val question = parseQuestion(q) ?: return null

        if (question.type != 1) {
            return buildResponse(q, question, null)
        }

        val ip = resolver.resolve(question.name)
        return buildResponse(q, question, ip)
    }

    private fun parseQuestion(q: ByteArray): Question? {
        var idx = 12
        val name = StringBuilder()

        while (idx < q.size) {
            val len = q[idx].toInt() and 0xFF

            if (len == 0) {
                idx++
                break
            }

            if ((len and 0xC0) == 0xC0) {
                idx += 2
                break
            }

            if (name.isNotEmpty()) {
                name.append('.')
            }

            if (idx + 1 + len > q.size) {
                return null
            }

            for (i in 1..len) {
                val c = q[idx + i].toInt() and 0xFF
                name.append(c.toChar())
            }

            idx += len + 1
        }

        if (idx + 4 > q.size) return null

        val type = PacketUtils.readShort(q, idx)
        val end = idx + 4

        return Question(name.toString(), type, end)
    }

    private fun buildResponse(
        q: ByteArray,
        question: Question,
        ip: String?
    ): ByteArray {
        val out = ByteArrayOutputStream()

        out.write(q[0].toInt())
        out.write(q[1].toInt())

        out.write(0x81)
        out.write(0x80)

        val answerCount = if (ip != null && question.type == 1) 1 else 0

        writeShort(out, 1)
        writeShort(out, answerCount)
        writeShort(out, 0)
        writeShort(out, 0)

        out.write(q, 12, question.end - 12)

        if (answerCount == 1) {
            out.write(0xC0)
            out.write(0x0C)

            writeShort(out, 1)
            writeShort(out, 1)
            writeInt(out, 300)
            writeShort(out, 4)

            val ipInt = PacketUtils.ipToInt(ip!!)
            out.write((ipInt ushr 24) and 0xFF)
            out.write((ipInt ushr 16) and 0xFF)
            out.write((ipInt ushr 8) and 0xFF)
            out.write(ipInt and 0xFF)
        }

        return out.toByteArray()
    }

    private fun writeShort(out: ByteArrayOutputStream, value: Int) {
        out.write((value shr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeInt(out: ByteArrayOutputStream, value: Int) {
        out.write((value shr 24) and 0xFF)
        out.write((value shr 16) and 0xFF)
        out.write((value shr 8) and 0xFF)
        out.write(value and 0xFF)
    }
}
