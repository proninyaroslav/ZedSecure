package dev.cluvex.zedsecure.platform

import org.junit.Assert.*
import org.junit.Test
import java.net.URL
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread
import com.sun.net.httpserver.HttpServer

class SubscriptionRedirectTest {
    @Test fun originIncludesSchemeHostAndEffectivePort() {
        fun same(a: String, b: String) = sameHttpOrigin(URL(a), URL(b))
        assertTrue(same("https://example.com/a", "https://EXAMPLE.com:443/b"))
        assertFalse(same("http://example.com", "https://example.com"))
        assertFalse(same("https://example.com", "http://example.com"))
        assertFalse(same("https://example.com", "https://other.com"))
        assertFalse(same("https://example.com", "https://example.com:444"))
    }
    @Test fun sendsHeadersOnlyToOriginalOriginAndRespectsDisabledSetting() {
        val seen = mutableListOf<Pair<String, String?>>()
        val destination = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val source = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        destination.createContext("/") { exchange ->
            seen += exchange.requestHeaders.getFirst("User-Agent") to exchange.requestHeaders.getFirst("x-hwid")
            assertNull(exchange.requestHeaders.getFirst("x-device-model"))
            exchange.sendResponseHeaders(200, 0)
            exchange.close()
        }
        source.createContext("/") { exchange ->
            seen += exchange.requestHeaders.getFirst("User-Agent") to exchange.requestHeaders.getFirst("x-hwid")
            if (exchange.requestURI.path == "/start") {
                exchange.responseHeaders.add("Location", "/next")
            } else {
                exchange.responseHeaders.add("Location", "http://127.0.0.1:${destination.address.port}/end")
            }
            exchange.sendResponseHeaders(302, -1)
            exchange.close()
        }
        source.start(); destination.start()
        try {
            val url = "http://127.0.0.1:${source.address.port}/start"
            val headers = mapOf("x-hwid" to "device", "x-device-model" to "model")
            httpGetResponse(url, "alternate-agent", null, headers, true, 3000, 3000)
            assertEquals(listOf("alternate-agent" to "device", "alternate-agent" to "device", "alternate-agent" to null), seen)
            seen.clear()
            httpGetResponse(url, "primary-agent", null, emptyMap(), true, 3000, 3000)
            assertEquals(listOf("primary-agent" to null, "primary-agent" to null, "primary-agent" to null), seen)
        } finally { source.stop(0); destination.stop(0) }
    }
    @Test fun socksRequestsKeepHeadersForSameOriginAndStripThemAcrossPorts() {
        val seen = java.util.Collections.synchronizedList(mutableListOf<String?>())
        val target = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val source = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        target.createContext("/") { e -> seen.add(e.requestHeaders.getFirst("x-hwid")); e.sendResponseHeaders(200, -1); e.close() }
        source.createContext("/") { e ->
            seen.add(e.requestHeaders.getFirst("x-hwid"))
            e.responseHeaders.add("Location", if (e.requestURI.path == "/start") "/next" else "http://127.0.0.1:${target.address.port}/")
            e.sendResponseHeaders(302, -1); e.close()
        }
        val proxy = ServerSocket(0)
        val listener = thread(isDaemon = true) {
            while (!proxy.isClosed) {
                val client = try { proxy.accept() } catch (_: java.io.IOException) { break }
                thread(isDaemon = true) {
                    client.use { socket ->
                        val input = socket.getInputStream(); val output = socket.getOutputStream()
                        check(input.read() == 5); val count = input.read(); repeat(count) { input.read() }
                        output.write(byteArrayOf(5, 0)); output.flush()
                        check(input.read() == 5); check(input.read() == 1); input.read()
                        val type = input.read()
                        val host = when (type) {
                            1 -> java.net.InetAddress.getByAddress(input.readNBytes(4)).hostAddress
                            3 -> String(input.readNBytes(input.read()))
                            else -> error("unexpected SOCKS address type")
                        }
                        val port = (input.read() shl 8) or input.read()
                        Socket(host, port).use { upstream ->
                            output.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 0, 0)); output.flush()
                            thread(isDaemon = true) { runCatching { input.copyTo(upstream.getOutputStream()) } }
                            runCatching { upstream.getInputStream().copyTo(output) }
                        }
                    }
                }
            }
        }
        source.start(); target.start()
        try {
            httpGetResponse("http://127.0.0.1:${source.address.port}/start", "fallback", proxy.localPort,
                mapOf("x-hwid" to "device", "x-device-os" to "Android"), true, 3000, 3000)
            assertEquals(listOf("device", "device", null), seen.toList())
        } finally { proxy.close(); listener.join(1000); source.stop(0); target.stop(0) }
    }
}
