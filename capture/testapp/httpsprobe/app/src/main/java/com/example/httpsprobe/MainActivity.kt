package com.example.httpsprobe

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioGroup
import android.widget.TextView
import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

/**
 * HttpsProbe — the test app for the Android capture tools.
 *
 * Enter a URL, pick GET/POST, and fire HTTPS requests (via HttpURLConnection, which
 * uses Conscrypt — so the capture's frida TLS-keylog hook sees real traffic). It can
 * also be driven programmatically for scripted capture tests; see [handleIntent].
 */
class MainActivity : Activity() {

    private val io = Executors.newSingleThreadExecutor()

    private lateinit var urlInput: EditText
    private lateinit var bodyInput: EditText
    private lateinit var methodGroup: RadioGroup
    private lateinit var response: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        urlInput = findViewById(R.id.url)
        bodyInput = findViewById(R.id.body)
        methodGroup = findViewById(R.id.method)
        response = findViewById(R.id.response)
        findViewById<Button>(R.id.send).setOnClickListener { fire(read(), times = 1) }
        addPresets(findViewById(R.id.presets))
        urlInput.setText("https://example.com")
        handleIntent(intent)
    }

    // singleTop: a fresh `am start` while running re-fires instead of restarting.
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    /**
     * Programmatic entry — intent extras or a deeplink. Prefills the UI and fires the
     * request(s). Examples:
     *
     *   # intent extras (no URL-encoding needed)
     *   am start -n com.example.httpsprobe/.MainActivity \
     *     --es url https://example.com --es method POST --es body '{"k":1}' --ei times 3
     *
     *   # plain http(s) link → GET it
     *   am start -a android.intent.action.VIEW -d 'https://example.com'
     *
     *   # custom deeplink (url-encode the url= value)
     *   am start -a android.intent.action.VIEW \
     *     -d 'httpsprobe://request?url=https%3A%2F%2Fexample.com&method=GET&times=2'
     */
    private fun handleIntent(intent: Intent?) {
        if (intent == null) return
        var url = intent.getStringExtra("url")
        var method = intent.getStringExtra("method")
        var body = intent.getStringExtra("body")
        var times = intent.getIntExtra("times", 0)
        val data: Uri? = intent.data
        if (url == null && data != null) {
            if (data.scheme.equals("httpsprobe", ignoreCase = true)) {
                url = data.getQueryParameter("url")
                method = method ?: data.getQueryParameter("method")
                body = body ?: data.getQueryParameter("body")
                if (times == 0) times = data.getQueryParameter("times")?.toIntOrNull() ?: 0
            } else {
                url = data.toString()  // a direct http/https link
            }
        }
        if (url.isNullOrBlank()) return
        urlInput.setText(url)
        method?.let { methodGroup.check(if (it.equals("POST", true)) R.id.post else R.id.get) }
        body?.let { bodyInput.setText(it) }
        fire(read(), times = if (times > 0) times else 1)
    }

    private data class Req(val url: String, val method: String, val body: String)

    private fun read() = Req(
        urlInput.text.toString().trim(),
        if (methodGroup.checkedRadioButtonId == R.id.post) "POST" else "GET",
        bodyInput.text.toString(),
    )

    private fun addPresets(container: LinearLayout) {
        val presets = listOf(
            Triple("example.com", "https://example.com", "GET"),
            Triple("httpbin GET", "https://httpbin.org/get", "GET"),
            Triple("httpbin POST", "https://httpbin.org/post", "POST"),
            Triple("redirect x2", "https://httpbin.org/redirect/2", "GET"),
        )
        for ((label, url, method) in presets) {
            container.addView(Button(this).apply {
                text = label
                setOnClickListener {
                    urlInput.setText(url)
                    methodGroup.check(if (method == "POST") R.id.post else R.id.get)
                    fire(read(), times = 1)
                }
            })
        }
    }

    private fun fire(req: Req, times: Int) {
        if (req.url.isBlank()) {
            response.text = "enter a URL"
            return
        }
        response.text = "… ${req.method} ${req.url}" + if (times > 1) "  ×$times" else ""
        io.execute {
            val out = StringBuilder()
            for (i in 1..times) {
                val line = runCatching { request(req) }
                    .getOrElse { "error: ${it.javaClass.simpleName}: ${it.message}" }
                out.append(if (times > 1) "[$i] " else "").append(line).append("\n")
                runOnUiThread { response.text = out.toString() }
            }
        }
    }

    private fun request(req: Req): String {
        val start = System.nanoTime()
        val conn = (URL(req.url).openConnection() as HttpURLConnection).apply {
            requestMethod = req.method
            connectTimeout = 15_000
            readTimeout = 15_000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "HttpsProbe/1.0")
            if (req.method == "POST") {
                doOutput = true
                if (req.body.isNotEmpty()) outputStream.use { it.write(req.body.toByteArray()) }
            }
        }
        try {
            val code = conn.responseCode
            val stream = if (code in 200..399) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader()?.use(BufferedReader::readText) ?: ""
            val ms = (System.nanoTime() - start) / 1_000_000
            // logcat marker so a scripted test can confirm the request fired/completed.
            Log.i(TAG, "${req.method} ${req.url} -> $code ${text.length}B ${ms}ms")
            return "$code ${conn.responseMessage}  ${text.length}B  ${ms}ms\n${text.take(2000)}"
        } finally {
            conn.disconnect()
        }
    }

    override fun onDestroy() {
        io.shutdownNow()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "HttpsProbe"
    }
}
