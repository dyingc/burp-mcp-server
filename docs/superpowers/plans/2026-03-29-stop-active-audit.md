# Stop Active Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `stop_active_audit` MCP tool that stops running crawl/audit tasks immediately, with optional ID targeting.

**Architecture:** Introduce `ActiveAuditRegistry` to track all MCP-started crawl/audit tasks by generated ID. Modify `start_active_audit` and `start_active_audit_for_request` to register tasks and return IDs. Add `stop_active_audit` tool that calls `Task.delete()` and interrupts polling threads. Verify with real E2E against `https://ginandjuice.shop`.

**Tech Stack:** Kotlin, Burp Montoya API (`Task.delete()`), MockK, JUnit 5

### Codex Discussion Consensus (2026-03-29, 1 round)
- **Decision**: Add `synchronized` to registry, per-entry try-catch in stop methods, positive-path integration tests
- **My position**: ConcurrentHashMap alone was sufficient; simple Int/Boolean return types
- **Codex's position**: Race conditions in compound operations; `delete()` exceptions create orphan tasks; integration tests lack positive path
- **Resolution**: Agreed on sync + try-catch. Disagreed on result objects (YAGNI) — string messages with failure info are sufficient
- **Reasoning**: `stopAll` doing `toMap()` then `clear()` has a race window; `delete()` has no documented idempotency guarantee
- **Rejected alternatives**: Result objects with stoppedIds/failedIds (over-engineering), companion object for registry (test pollution risk)

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `src/main/kotlin/net/portswigger/mcp/tools/ActiveAuditRegistry.kt` | Create | Track active crawl/audit tasks by ID |
| `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt` | Modify | Register tasks in registry, add `stop_active_audit` tool, return IDs |
| `src/test/kotlin/net/portswigger/mcp/tools/ActiveAuditRegistryTest.kt` | Create | Unit tests for registry |
| `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt` | Modify | Integration tests for stop tool |

---

### Task 0: E2E Red — Demonstrate the Problem

**Purpose:** Prove that a running scan cannot be stopped via MCP today.

- [ ] **Step 1: Start an active audit on ginandjuice.shop**

Use MCP tool: `mcp__burp__start_active_audit` with `targetUrl=https://ginandjuice.shop`, `scanDurationSeconds=300`.

- [ ] **Step 2: Observe issues accumulating**

Use MCP tool: `mcp__burp__get_scanner_issues` with `count=5, offset=0`. Wait ~30s, call again. Issues should be growing.

- [ ] **Step 3: Confirm no stop tool exists**

There is no `mcp__burp__stop_active_audit` tool available. The scan will run for the full 300 seconds. This is the Red state. Stop the scan manually from Burp UI for cleanup.

---

### Task 1: ActiveAuditRegistry — Failing Tests

**Files:**
- Create: `src/test/kotlin/net/portswigger/mcp/tools/ActiveAuditRegistryTest.kt`

- [ ] **Step 1: Write failing tests for the registry**

```kotlin
package net.portswigger.mcp.tools

import burp.api.montoya.scanner.Crawl
import burp.api.montoya.scanner.audit.Audit
import io.mockk.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class ActiveAuditRegistryTest {

    private val registry = ActiveAuditRegistry()

    @BeforeEach
    fun setup() {
        registry.clear()
    }

    @Test
    fun `register returns incrementing IDs`() {
        val audit1 = mockk<Audit>(relaxed = true)
        val audit2 = mockk<Audit>(relaxed = true)

        val id1 = registry.register(audit = audit1)
        val id2 = registry.register(audit = audit2)

        assertEquals("audit-1", id1)
        assertEquals("audit-2", id2)
    }

    @Test
    fun `register with crawl stores both`() {
        val crawl = mockk<Crawl>(relaxed = true)
        val audit = mockk<Audit>(relaxed = true)

        val id = registry.register(crawl = crawl, audit = audit)
        assertNotNull(id)
    }

    @Test
    fun `stopAll deletes all tasks and interrupts threads`() {
        val crawl = mockk<Crawl>(relaxed = true)
        val audit1 = mockk<Audit>(relaxed = true)
        val audit2 = mockk<Audit>(relaxed = true)
        val thread = mockk<Thread>(relaxed = true)

        registry.register(crawl = crawl, audit = audit1, pollingThread = thread)
        registry.register(audit = audit2)

        val result = registry.stopAll()

        assertEquals(2, result.total)
        assertEquals(0, result.failed)
        verify { crawl.delete() }
        verify { audit1.delete() }
        verify { audit2.delete() }
        verify { thread.interrupt() }
    }

    @Test
    fun `stopAll on empty registry returns zero`() {
        val result = registry.stopAll()
        assertEquals(0, result.total)
    }

    @Test
    fun `stopById deletes specific task and returns message`() {
        val audit1 = mockk<Audit>(relaxed = true)
        val audit2 = mockk<Audit>(relaxed = true)

        val id1 = registry.register(audit = audit1)
        registry.register(audit = audit2)

        val result = registry.stopById(id1)

        assertNotNull(result)
        assertTrue(result!!.contains("Stopped"))
        verify { audit1.delete() }
        verify(exactly = 0) { audit2.delete() }
    }

    @Test
    fun `stopById with unknown ID returns null`() {
        val audit = mockk<Audit>(relaxed = true)
        registry.register(audit = audit)

        val result = registry.stopById("audit-999")

        assertNull(result)
        verify(exactly = 0) { audit.delete() }
    }

    @Test
    fun `stopById with polling thread interrupts it`() {
        val audit = mockk<Audit>(relaxed = true)
        val thread = mockk<Thread>(relaxed = true)

        val id = registry.register(audit = audit, pollingThread = thread)
        registry.stopById(id)

        verify { thread.interrupt() }
    }

    @Test
    fun `stopAll clears registry`() {
        val audit = mockk<Audit>(relaxed = true)
        registry.register(audit = audit)

        registry.stopAll()
        val result = registry.stopAll()

        assertEquals(0, result.total)
    }

    @Test
    fun `stopById removes entry from registry`() {
        val audit = mockk<Audit>(relaxed = true)
        val id = registry.register(audit = audit)

        assertNotNull(registry.stopById(id))
        assertNull(registry.stopById(id))
    }

    @Test
    fun `stopAll continues when delete throws and reports failures`() {
        val audit1 = mockk<Audit>(relaxed = true)
        val audit2 = mockk<Audit>(relaxed = true)

        every { audit1.delete() } throws RuntimeException("delete failed")

        registry.register(audit = audit1)
        registry.register(audit = audit2)

        val result = registry.stopAll()

        assertEquals(2, result.total)
        assertEquals(1, result.failed)
        assertTrue(result.errors.any { it.contains("delete failed") })
        verify { audit2.delete() }
    }

    @Test
    fun `stopById returns failure message when delete throws`() {
        val audit = mockk<Audit>(relaxed = true)
        every { audit.delete() } throws RuntimeException("delete failed")

        val id = registry.register(audit = audit)
        val result = registry.stopById(id)

        assertNotNull(result)
        assertTrue(result!!.contains("failed"))
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew test --tests "net.portswigger.mcp.tools.ActiveAuditRegistryTest" --info`
Expected: Compilation error — `ActiveAuditRegistry` class does not exist yet.

---

### Task 2: ActiveAuditRegistry — Implementation

**Files:**
- Create: `src/main/kotlin/net/portswigger/mcp/tools/ActiveAuditRegistry.kt`

- [ ] **Step 1: Implement ActiveAuditRegistry**

```kotlin
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
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `./gradlew test --tests "net.portswigger.mcp.tools.ActiveAuditRegistryTest" --info`
Expected: All 11 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/tools/ActiveAuditRegistry.kt src/test/kotlin/net/portswigger/mcp/tools/ActiveAuditRegistryTest.kt
git commit -m "feat: add ActiveAuditRegistry to track and stop audit tasks"
```

---

### Task 3: Stop Tool Integration Tests — Failing

**Files:**
- Modify: `src/test/kotlin/net/portswigger/mcp/tools/ToolsKtTest.kt`

- [ ] **Step 1: Add ActiveAuditToolsTests nested class with failing tests**

Add inside `ToolsKtTest`, after `CollaboratorToolsTests`. This requires the same Professional edition setup as the Collaborator tests — restart the server with Pro edition mock.

```kotlin
@Nested
inner class ActiveAuditToolsTests {
    private val scanner = mockk<burp.api.montoya.scanner.Scanner>(relaxed = true)

    @BeforeEach
    fun setupProfessional() {
        val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
        val version = mockk<burp.api.montoya.core.Version>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
        every { burpSuite.taskExecutionEngine() } returns mockk(relaxed = true)
        every { burpSuite.exportProjectOptionsAsJson() } returns "{}"
        every { burpSuite.exportUserOptionsAsJson() } returns "{}"
        every { burpSuite.importProjectOptionsFromJson(any()) } just runs
        every { burpSuite.importUserOptionsFromJson(any()) } just runs
        every { api.scanner() } returns scanner

        every { config.allowActiveScanTooling } returns true

        serverManager.stop {}
        serverStarted = false
        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")
            client.connectToServer("http://127.0.0.1:${testPort}")
        }
    }

    @Test
    fun `stop_active_audit tool should be registered in professional edition`() {
        runBlocking {
            val tools = client.listTools()
            assertTrue(tools.any { it.name == "stop_active_audit" })
        }
    }

    @Test
    fun `stop all audits should return count`() {
        runBlocking {
            val result = client.callTool("stop_active_audit", emptyMap())
            delay(100)
            val text = result.expectTextContent()
            assertTrue(text.contains("0"), "Should report 0 stopped when none running")
        }
    }

    @Test
    fun `stop with invalid audit ID should return not found`() {
        runBlocking {
            val result = client.callTool(
                "stop_active_audit", mapOf(
                    "auditId" to "audit-999"
                )
            )
            delay(100)
            val text = result.expectTextContent()
            assertTrue(text.contains("not found"), "Should report not found for invalid ID")
        }
    }

    @Test
    fun `stop should be denied when active scan tooling disabled`() {
        every { config.allowActiveScanTooling } returns false

        runBlocking {
            val result = client.callTool("stop_active_audit", emptyMap())
            delay(100)
            val text = result.expectTextContent()
            assertTrue(text.contains("disabled"), "Should report disabled")
        }
    }

    @Test
    fun `start then stop by ID should delete the task`() {
        val mockCrawl = mockk<burp.api.montoya.scanner.Crawl>(relaxed = true)
        val mockAudit = mockk<burp.api.montoya.scanner.audit.Audit>(relaxed = true)
        val mockScope = mockk<burp.api.montoya.sitemap.SiteMap>(relaxed = true)
        val mockScopeTarget = mockk<burp.api.montoya.scope.Scope>(relaxed = true)

        every { scanner.startCrawl(any()) } returns mockCrawl
        every { scanner.startAudit(any()) } returns mockAudit
        every { api.siteMap() } returns mockScope
        every { api.scope() } returns mockScopeTarget

        mockkStatic(CrawlConfiguration::class)
        mockkStatic(AuditConfiguration::class)
        mockkStatic(HttpRequest::class)
        every { CrawlConfiguration.crawlConfiguration(any<String>()) } returns mockk(relaxed = true)
        every { AuditConfiguration.auditConfiguration(any()) } returns mockk(relaxed = true)
        every { HttpRequest.httpRequestFromUrl(any<String>()) } returns mockk(relaxed = true)

        runBlocking {
            val startResult = client.callTool(
                "start_active_audit", mapOf(
                    "targetUrl" to "https://example.com",
                    "scanDurationSeconds" to 300
                )
            )
            delay(100)
            val startText = startResult.expectTextContent()
            assertTrue(startText.contains("auditId:"), "Should contain auditId")

            val auditId = Regex("auditId: (audit-\\d+)").find(startText)!!.groupValues[1]

            val stopResult = client.callTool(
                "stop_active_audit", mapOf(
                    "auditId" to auditId
                )
            )
            delay(100)
            val stopText = stopResult.expectTextContent()
            assertTrue(stopText.contains("Stopped"), "Should confirm stopped")
        }

        verify { mockCrawl.delete() }
        verify { mockAudit.delete() }

        unmockkStatic(CrawlConfiguration::class)
        unmockkStatic(AuditConfiguration::class)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew test --tests "net.portswigger.mcp.tools.ToolsKtTest\$ActiveAuditToolsTests" --info`
Expected: FAIL — `stop_active_audit` tool does not exist yet.

---

### Task 4: Wire Up Registry and Stop Tool — Implementation

**Files:**
- Modify: `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`

- [ ] **Step 1: Add StopActiveAudit data class**

Add after the `StartActiveAuditForRequest` data class at the bottom of the file:

```kotlin
@Serializable
data class StopActiveAudit(
    val auditId: String? = null
)
```

- [ ] **Step 2: Create registry and wire into registerTools**

At the top of `registerTools`, create the shared registry (inside the `if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL)` block, before the existing audit tools):

```kotlin
val auditRegistry = ActiveAuditRegistry()
```

- [ ] **Step 3: Modify StartActiveAudit handler to register tasks and return ID**

Replace the `mcpTool<StartActiveAudit>(...)` block (lines 320-367). Key changes:
- Register crawl, audit, and polling thread in `auditRegistry`
- The polling thread checks `Thread.currentThread().isInterrupted` to exit early
- Return message includes the audit ID

```kotlin
mcpTool<StartActiveAudit>(
    "Starts a Burp active scan (crawl + audit) for the target URL. " +
    "Returns an auditId that can be used with stop_active_audit. " +
    "Use get_scanner_issues to retrieve findings."
) {
    if (!config.allowActiveScanTooling) {
        return@mcpTool activeScanDisabledMessage
    }

    api.logging().logToOutput("MCP start_active_audit: starting active audit for $targetUrl")
    api.scope().includeInScope(targetUrl)

    val targetHost = java.net.URI(targetUrl).host

    val crawlConfig = CrawlConfiguration.crawlConfiguration(targetUrl)
    val crawl = api.scanner().startCrawl(crawlConfig)
    api.logging().logToOutput("MCP start_active_audit: crawl started for $targetUrl")

    val auditConfig = AuditConfiguration.auditConfiguration(
        BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
    )
    val audit = api.scanner().startAudit(auditConfig)
    api.logging().logToOutput("MCP start_active_audit: audit started for $targetUrl")
    audit.addRequest(HttpRequest.httpRequestFromUrl(targetUrl))
    api.logging().logToOutput("MCP start_active_audit: added initial audit request for $targetUrl")

    val seen = mutableSetOf<String>()
    val pollIntervalMs = 2000L
    val maxIterations = scanDurationSeconds * 1000 / pollIntervalMs

    val pollingThread = Thread {
        repeat(maxIterations.toInt()) {
            if (Thread.currentThread().isInterrupted) return@Thread
            try {
                Thread.sleep(pollIntervalMs)
                addMatchingResponsesToAudit(
                    audit = audit,
                    requestResponses = api.siteMap().requestResponses(),
                    targetHost = targetHost,
                    seen = seen,
                    logging = api.logging(),
                )
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return@Thread
            } catch (_: Exception) {
            }
        }
        api.logging().logToOutput("MCP start_active_audit: scan duration reached ($scanDurationSeconds seconds)")
    }.apply { isDaemon = true }

    val auditId = auditRegistry.register(crawl = crawl, audit = audit, pollingThread = pollingThread)
    pollingThread.start()

    api.logging().logToOutput("MCP start_active_audit: registered as $auditId")
    "Active scan started for $targetUrl (auditId: $auditId). Use get_scanner_issues to retrieve findings. Use stop_active_audit to stop."
}
```

- [ ] **Step 4: Modify StartActiveAuditForRequest handler to register and return ID**

Replace the `mcpTool<StartActiveAuditForRequest>(...)` block (lines 369-403). Key change: register audit in `auditRegistry` and return ID.

```kotlin
mcpTool<StartActiveAuditForRequest>(
    "Starts a focused Burp active audit for a specific HTTP request. " +
    "Returns an auditId that can be used with stop_active_audit. " +
    "Use get_scanner_issues to retrieve findings."
) {
    if (!config.allowActiveScanTooling) {
        return@mcpTool activeScanDisabledMessage
    }

    val target = parseFocusedAuditTarget(targetUrl)
    validateFocusedAuditRequest(target, request)
    api.logging().logToOutput("MCP start_active_audit_for_request: starting focused audit for $targetUrl")
    api.scope().includeInScope(targetUrl)

    val auditConfig = AuditConfiguration.auditConfiguration(
        BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
    )
    val audit = api.scanner().startAudit(auditConfig)
    api.logging().logToOutput("MCP start_active_audit_for_request: audit started for $targetUrl")

    val service = HttpService.httpService(target.host, target.port, target.usesHttps)
    val fixedRequest = request.replace("\r", "").replace("\n", "\r\n")
    val httpRequest = HttpRequest.httpRequest(service, fixedRequest)

    if (response != null) {
        val httpResponse = HttpResponse.httpResponse(response)
        val requestResponse = HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse)
        audit.addRequestResponse(requestResponse)
        api.logging().logToOutput("MCP start_active_audit_for_request: injected request-response for $targetUrl")
    } else {
        audit.addRequest(httpRequest)
        api.logging().logToOutput("MCP start_active_audit_for_request: injected request for $targetUrl")
    }

    val auditId = auditRegistry.register(audit = audit)
    api.logging().logToOutput("MCP start_active_audit_for_request: registered as $auditId")
    "Focused active audit started for $targetUrl (auditId: $auditId). Use get_scanner_issues to retrieve findings. Use stop_active_audit to stop."
}
```

- [ ] **Step 5: Add stop_active_audit tool**

Add right after the `StartActiveAuditForRequest` tool block, still inside the Professional edition `if` block:

```kotlin
mcpTool<StopActiveAudit>(
    "Stops running active audits started via MCP. " +
    "With no auditId, stops all. With an auditId, stops only that audit."
) {
    if (!config.allowActiveScanTooling) {
        return@mcpTool activeScanDisabledMessage
    }

    if (auditId != null) {
        val message = auditRegistry.stopById(auditId)
        if (message != null) {
            api.logging().logToOutput("MCP stop_active_audit: $message")
            message
        } else {
            api.logging().logToOutput("MCP stop_active_audit: $auditId not found")
            "Audit $auditId not found"
        }
    } else {
        val result = auditRegistry.stopAll()
        val message = if (result.failed > 0) {
            "Stopped ${result.total} audit(s); ${result.failed} failed: ${result.errors.joinToString(", ")}"
        } else {
            "Stopped ${result.total} audit(s)"
        }
        api.logging().logToOutput("MCP stop_active_audit: $message")
        message
    }
}
```

- [ ] **Step 6: Run all tests**

Run: `./gradlew test --info`
Expected: All tests PASS (both registry unit tests and integration tests).

- [ ] **Step 7: Commit**

```bash
git add src/main/kotlin/net/portswigger/mcp/tools/Tools.kt
git commit -m "feat: add stop_active_audit tool with registry tracking"
```

---

### Task 5: Build

- [ ] **Step 1: Build the shadow JAR**

Run: `./gradlew shadowJar`
Expected: BUILD SUCCESSFUL, JAR at `build/libs/burp-mcp-server-*.jar`

- [ ] **Step 2: Hand off to user for installation**

User installs the new JAR into Burp Pro.

---

### Task 6: E2E Green — Verify the Fix

- [ ] **Step 1: Start an active audit**

Use MCP tool: `mcp__burp__start_active_audit` with `targetUrl=https://ginandjuice.shop`, `scanDurationSeconds=300`.
Expected: Response contains an `auditId` like `audit-1`.

- [ ] **Step 2: Observe issues accumulating**

Wait ~30s, use `mcp__burp__get_scanner_issues` with `count=5, offset=0`. Note the issue count.

- [ ] **Step 3: Stop the audit**

Use MCP tool: `mcp__burp__stop_active_audit` with the `auditId` from step 1.
Expected: Response says "Stopped audit audit-1".

- [ ] **Step 4: Verify issues stopped growing**

Wait ~30s, use `mcp__burp__get_scanner_issues` again. Issue count should be stable (not growing).

- [ ] **Step 5: Test stop all (no auditId)**

Start 2 new audits, then call `mcp__burp__stop_active_audit` with no parameters.
Expected: "Stopped 2 audit(s)".

- [ ] **Step 6: Test invalid ID**

Call `mcp__burp__stop_active_audit` with `auditId=audit-999`.
Expected: "Audit audit-999 not found".
