package dev.cluvex.zedsecure.platform

import java.net.HttpURLConnection
import java.net.URL

internal actual fun httpGetText(
    url: String,
    userAgent: String,
    connectTimeoutMs: Int,
    readTimeoutMs: Int,
): String {
    val connection = (URL(url).openConnection() as HttpURLConnection).apply {
        connectTimeout = connectTimeoutMs
        readTimeout = readTimeoutMs
        instanceFollowRedirects = true
        setRequestProperty("User-Agent", userAgent)
    }
    try {
        if (connection.responseCode !in 200..299) {
            throw IllegalStateException("HTTP ${connection.responseCode}")
        }
        return connection.inputStream.bufferedReader().use { it.readText() }
    } catch (e: NullPointerException) {
        throw platformHttpFailure(e)
    } finally {
        connection.disconnectQuietly()
    }
}

internal actual fun httpGetResponse(
    url: String,
    userAgent: String,
    socksPort: Int?,
    deviceHeaders: Map<String, String>,
    safeRedirects: Boolean,
    connectTimeoutMs: Int,
    readTimeoutMs: Int,
): HttpTextResponse {
    if (socksPort != null && JvmRuntime.resolvesThroughProxy) {
        val headers = mutableMapOf("User-Agent" to userAgent)
        headers.putAll(deviceHeaders)
        val response = rawHttpViaSocks("GET", url, headers, null, socksPort, connectTimeoutMs, readTimeoutMs, stripDeviceHeadersOnCrossOrigin = safeRedirects)
        if (response.code !in 200..299) throw IllegalStateException("HTTP ${response.code}")
        return HttpTextResponse(response.code, response.body, response.headers)
    }
    var target = URL(url)
    var sendDeviceHeaders = deviceHeaders.isNotEmpty()
    var redirects = 0
    while (true) {
        val connection = (
            if (socksPort != null) {
                target.openConnection(
                    java.net.Proxy(java.net.Proxy.Type.SOCKS, java.net.InetSocketAddress.createUnresolved("127.0.0.1", socksPort)),
                )
            } else {
                target.openConnection()
            }
            ) as HttpURLConnection
        connection.apply {
            connectTimeout = connectTimeoutMs
            readTimeout = readTimeoutMs
            instanceFollowRedirects = !safeRedirects
            setRequestProperty("User-Agent", userAgent)
            if (sendDeviceHeaders) deviceHeaders.forEach { (name, value) -> setRequestProperty(name, value) }
        }
        try {
            val code = connection.responseCode
            val location = connection.getHeaderField("Location")
            if (safeRedirects && code in listOf(301, 302, 303, 307, 308) && location != null && redirects < 20) {
                val next = URL(target, location)
                if (next.protocol !in listOf("http", "https")) throw IllegalStateException("HTTP $code")
                if (!sameHttpOrigin(target, next)) sendDeviceHeaders = false
                target = next
                redirects++
                continue
            }
            if (code !in 200..299) throw IllegalStateException("HTTP $code")

            val headers = connection.headerFields.orEmpty().entries
                .mapNotNull { (name, values) ->
                    val key = name?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
                    val value = values?.firstOrNull() ?: return@mapNotNull null
                    key to value
                }
                .toMap()
            val body = connection.inputStream.bufferedReader().use { it.readText() }
            return HttpTextResponse(code, body, headers)
        } catch (e: NullPointerException) {
            throw platformHttpFailure(e)
        } finally {
            connection.disconnectQuietly()
        }
    }
}

internal actual suspend fun httpJson(
    method: String,
    url: String,
    headers: Map<String, String>,
    body: String?,
    connectTimeoutMs: Int,
    readTimeoutMs: Int,
    socksPort: Int?,
): HttpTextResponse = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
    if (socksPort != null && JvmRuntime.resolvesThroughProxy) {
        val response = rawHttpViaSocks(method, url, headers, body?.encodeToByteArray(), socksPort, connectTimeoutMs, readTimeoutMs)
        return@withContext HttpTextResponse(response.code, response.body, response.headers)
    }
    val target = URL(url)

    val raw = if (socksPort != null) {
        target.openConnection(
            java.net.Proxy(java.net.Proxy.Type.SOCKS, java.net.InetSocketAddress.createUnresolved("127.0.0.1", socksPort)),
        )
    } else {
        target.openConnection()
    }
    val connection = (raw as HttpURLConnection).apply {
        requestMethod = method
        connectTimeout = connectTimeoutMs

        readTimeout = readTimeoutMs
        instanceFollowRedirects = true
        headers.forEach { (k, v) -> setRequestProperty(k, v) }
    }
    try {
        if (body != null) {
            connection.doOutput = true
            connection.outputStream.use { it.write(body.encodeToByteArray()) }
        }
        val code = connection.responseCode

        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val text = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
        val responseHeaders = connection.headerFields.orEmpty().entries
            .mapNotNull { (name, values) ->
                val key = name?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
                val value = values?.firstOrNull() ?: return@mapNotNull null
                key to value
            }
            .toMap()
        HttpTextResponse(code, text, responseHeaders)
    } catch (e: NullPointerException) {
        throw platformHttpFailure(e)
    } finally {
        connection.disconnectQuietly()
    }
}

internal fun sameHttpOrigin(a: URL, b: URL): Boolean =
    a.protocol.equals(b.protocol, ignoreCase = true) &&
        a.host.equals(b.host, ignoreCase = true) &&
        (if (a.port == -1) a.defaultPort else a.port) == (if (b.port == -1) b.defaultPort else b.port)
