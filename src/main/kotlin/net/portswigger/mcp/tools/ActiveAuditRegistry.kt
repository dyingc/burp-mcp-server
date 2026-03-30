package net.portswigger.mcp.tools

import burp.api.montoya.scanner.Crawl
import burp.api.montoya.scanner.audit.Audit
import java.util.concurrent.atomic.AtomicInteger

data class ActiveAuditEntry(
    val crawl: Crawl?,
    val audit: Audit,
    val pollingThread: Thread?,
)

data class StopAllResult(val total: Int, val failed: Int, val errors: List<String>)

class ActiveAuditRegistry {
    private val entries = LinkedHashMap<String, ActiveAuditEntry>()
    private val counter = AtomicInteger(0)

    @Synchronized
    fun register(
        crawl: Crawl? = null,
        audit: Audit,
        pollingThread: Thread? = null,
    ): String {
        val id = "audit-${counter.incrementAndGet()}"
        entries[id] = ActiveAuditEntry(crawl, audit, pollingThread)
        return id
    }

    fun stopAll(): StopAllResult {
        val snapshot: Map<String, ActiveAuditEntry>
        synchronized(this) {
            snapshot = entries.toMap()
            entries.clear()
        }
        var failed = 0
        val errors = mutableListOf<String>()
        snapshot.forEach { (id, entry) ->
            try {
                entry.pollingThread?.interrupt()
            } catch (_: Exception) {}
            try {
                entry.audit.delete()
            } catch (e: Exception) {
                failed++
                errors.add("$id audit: ${e.message}")
            }
            try {
                entry.crawl?.delete()
            } catch (e: Exception) {
                failed++
                errors.add("$id crawl: ${e.message}")
            }
        }
        return StopAllResult(snapshot.size, failed, errors)
    }

    fun stopById(id: String): String? {
        val entry: ActiveAuditEntry
        synchronized(this) {
            entry = entries.remove(id) ?: return null
        }
        val errors = mutableListOf<String>()
        try {
            entry.pollingThread?.interrupt()
        } catch (_: Exception) {}
        try {
            entry.audit.delete()
        } catch (e: Exception) {
            errors.add("audit delete failed: ${e.message}")
        }
        try {
            entry.crawl?.delete()
        } catch (e: Exception) {
            errors.add("crawl delete failed: ${e.message}")
        }
        return if (errors.isEmpty()) {
            "Stopped audit $id"
        } else {
            "Stopped audit $id (${errors.joinToString("; ")})"
        }
    }

    @Synchronized
    fun clear() {
        entries.clear()
        counter.set(0)
    }
}
