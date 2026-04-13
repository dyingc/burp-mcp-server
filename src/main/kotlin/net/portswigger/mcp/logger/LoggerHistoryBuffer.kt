package net.portswigger.mcp.logger

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.message.requests.HttpRequest
import java.time.Instant
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.regex.Pattern

data class LoggerEntry(
    val time: Instant,
    val toolType: ToolType,
    val host: String?,
    val port: Int,
    val secure: Boolean,
    val method: String?,
    val path: String?,
    val statusCode: Int?,
    val request: String?,
    val response: String?,
    val hasResponse: Boolean
)

private const val PROTOCOL_ERROR_BODY = "\"Protocol error\""
private const val POLLUTION_THRESHOLD = 1

class LoggerHistoryBuffer(
    private val maxSize: Int = 10_000,
    private val api: MontoyaApi? = null
) : HttpHandler {

    private val buffer = ConcurrentLinkedDeque<LoggerEntry>()
    private val pendingRequests = ConcurrentHashMap<Int, Pair<Instant, HttpRequestToBeSent>>()
    private val consecutiveProtocolErrors = ConcurrentHashMap<String, Int>()
    private val probing = AtomicBoolean(false)
    private val probeThread = ThreadLocal<Boolean>()

    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
        pendingRequests[requestToBeSent.messageId()] = Instant.now() to requestToBeSent
        return RequestToBeSentAction.continueWith(requestToBeSent)
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
        val messageId = responseReceived.messageId()
        val pending = pendingRequests.remove(messageId)

        val time = pending?.first ?: Instant.now()
        val request = pending?.second

        val host = request?.httpService()?.host() ?: responseReceived.initiatingRequest()?.httpService()?.host()
        val port = request?.httpService()?.port() ?: responseReceived.initiatingRequest()?.httpService()?.port() ?: 0
        val secure = request?.httpService()?.secure() ?: responseReceived.initiatingRequest()?.httpService()?.secure() ?: false
        val statusCode = responseReceived.statusCode().toInt()

        val entry = LoggerEntry(
            time = time,
            toolType = responseReceived.toolSource().toolType(),
            host = host,
            port = port,
            secure = secure,
            method = request?.method() ?: responseReceived.initiatingRequest()?.method(),
            path = request?.path() ?: responseReceived.initiatingRequest()?.path(),
            statusCode = statusCode,
            request = request?.toString() ?: responseReceived.initiatingRequest()?.toString(),
            response = responseReceived.toString(),
            hasResponse = true
        )

        addEntry(entry)

        if (host != null && probeThread.get() != true) {
            trackPollution(host, port, secure, statusCode, responseReceived.toString(), entry.request)
        }

        return ResponseReceivedAction.continueWith(responseReceived)
    }

    private fun trackPollution(host: String, port: Int, secure: Boolean, statusCode: Int, responseText: String, requestText: String?) {
        val isH2Request = requestText != null && requestText.contains(" HTTP/2\r\n")
        if (isH2Request && statusCode == 400 && responseText.contains(PROTOCOL_ERROR_BODY)) {
            val count = consecutiveProtocolErrors.merge(host, 1) { old, _ -> old + 1 } ?: 1
            if (count >= POLLUTION_THRESHOLD && api != null && probing.compareAndSet(false, true)) {
                Thread {
                    try {
                        probeAndRecover(host, port, secure)
                    } finally {
                        probing.set(false)
                    }
                }.apply {
                    isDaemon = true
                    name = "mcp-h2-pollution-probe"
                    start()
                }
            }
        } else {
            consecutiveProtocolErrors.remove(host)
        }
    }

    private fun probeAndRecover(host: String, port: Int, secure: Boolean) {
        val api = this.api ?: return
        api.logging().logToOutput(
            "MCP Logger: detected $POLLUTION_THRESHOLD consecutive \"Protocol error\" responses for $host. Sending probe..."
        )

        try {
            probeThread.set(true)
            val service = HttpService.httpService(host, port, secure)
            val probeRequest = HttpRequest.httpRequest(service, "GET / HTTP/2\r\nHost: $host\r\n\r\n")
            val probeResponse = api.http().sendRequest(probeRequest, HttpMode.HTTP_2)
            val probeStatus = probeResponse?.response()?.statusCode()?.toInt()
            val probeBody = probeResponse?.response()?.toString() ?: ""

            if (probeStatus == 400 && probeBody.contains(PROTOCOL_ERROR_BODY)) {
                api.logging().logToOutput(
                    "MCP Logger: probe confirmed HTTP/2 connection pool pollution for $host. Resetting connections..."
                )
                resetH2Connections()
                api.logging().logToOutput("MCP Logger: HTTP/2 connection reset completed for $host.")
            } else {
                api.logging().logToOutput(
                    "MCP Logger: probe returned status $probeStatus for $host — not connection pollution. No action taken."
                )
            }
        } catch (e: Exception) {
            api.logging().logToError("MCP Logger: probe failed for $host: ${e.message}")
        } finally {
            probeThread.set(false)
            consecutiveProtocolErrors.remove(host)
        }
    }

    private fun resetH2Connections() {
        val api = this.api ?: return
        api.burpSuite().importProjectOptionsFromJson(
            """{"project_options":{"http":{"http2":{"enable_http2":false}}}}"""
        )
        api.burpSuite().importProjectOptionsFromJson(
            """{"project_options":{"http":{"http2":{"enable_http2":true}}}}"""
        )
    }

    private fun addEntry(entry: LoggerEntry) {
        buffer.addLast(entry)
        while (buffer.size > maxSize) {
            buffer.pollFirst()
        }
    }

    fun snapshot(): List<LoggerEntry> = buffer.toList()

    fun search(pattern: Pattern): List<LoggerEntry> {
        return buffer.filter { entry ->
            (entry.request != null && pattern.matcher(entry.request).find()) ||
                (entry.response != null && pattern.matcher(entry.response).find())
        }
    }
}
