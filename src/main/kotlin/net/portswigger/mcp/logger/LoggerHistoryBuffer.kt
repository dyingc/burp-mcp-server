package net.portswigger.mcp.logger

import burp.api.montoya.core.ToolType
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import java.time.Instant
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.ConcurrentHashMap
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

class LoggerHistoryBuffer(
    private val maxSize: Int = 10_000
) : HttpHandler {

    private val buffer = ConcurrentLinkedDeque<LoggerEntry>()
    private val pendingRequests = ConcurrentHashMap<Int, Pair<Instant, HttpRequestToBeSent>>()

    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
        pendingRequests[requestToBeSent.messageId()] = Instant.now() to requestToBeSent
        return RequestToBeSentAction.continueWith(requestToBeSent)
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
        val messageId = responseReceived.messageId()
        val pending = pendingRequests.remove(messageId)

        val time = pending?.first ?: Instant.now()
        val request = pending?.second

        val entry = LoggerEntry(
            time = time,
            toolType = responseReceived.toolSource().toolType(),
            host = request?.httpService()?.host() ?: responseReceived.initiatingRequest()?.httpService()?.host(),
            port = request?.httpService()?.port() ?: responseReceived.initiatingRequest()?.httpService()?.port() ?: 0,
            secure = request?.httpService()?.secure() ?: responseReceived.initiatingRequest()?.httpService()?.secure() ?: false,
            method = request?.method() ?: responseReceived.initiatingRequest()?.method(),
            path = request?.path() ?: responseReceived.initiatingRequest()?.path(),
            statusCode = responseReceived.statusCode().toInt(),
            request = request?.toString() ?: responseReceived.initiatingRequest()?.toString(),
            response = responseReceived.toString(),
            hasResponse = true
        )

        addEntry(entry)

        return ResponseReceivedAction.continueWith(responseReceived)
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
