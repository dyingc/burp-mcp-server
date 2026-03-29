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

    @Synchronized
    fun stopAll(): StopAllResult {
        val snapshot = entries.toMap()
        entries.clear()
        var failed = 0
        val errors = mutableListOf<String>()
        snapshot.forEach { (id, entry) ->
            try {
                entry.pollingThread?.interrupt()
                entry.crawl?.delete()
                entry.audit.delete()
            } catch (e: Exception) {
                failed++
                errors.add("$id: ${e.message}")
            }
        }
        return StopAllResult(snapshot.size, failed, errors)
    }

    @Synchronized
    fun stopById(id: String): String? {
        val entry = entries.remove(id) ?: return null
        return try {
            entry.pollingThread?.interrupt()
            entry.crawl?.delete()
            entry.audit.delete()
            "Stopped audit $id"
        } catch (e: Exception) {
            "Stopped audit $id but delete failed: ${e.message}"
        }
    }

    @Synchronized
    fun clear() {
        entries.clear()
        counter.set(0)
    }
}
