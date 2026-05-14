package cloud.parlisoncodecouture.securitycheck.http

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

data class HttpResult(
    val statusCode: Int,
    val headers: Map<String, List<String>>,
    val body: String,
) {
    val isSuccess: Boolean get() = statusCode in 200..299
}

class SupabaseHttpClient(private val config: SupabaseConfig) {
    private val client: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(config.connectTimeoutSeconds))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build()

    fun getWithKey(
        path: String,
        apiKey: String,
        extraHeaders: Map<String, String> = emptyMap(),
    ): HttpResult {
        val url = resolveUrl(path)
        val builder = HttpRequest.newBuilder(URI.create(url))
            .timeout(Duration.ofSeconds(config.requestTimeoutSeconds))
            .header("apikey", apiKey)
            .header("Authorization", "Bearer $apiKey")
            .header("Accept", "application/json")
            .GET()
        extraHeaders.forEach { (k, v) -> builder.header(k, v) }
        return execute(builder.build())
    }

    private fun resolveUrl(path: String): String =
        if (path.startsWith("http://") || path.startsWith("https://")) {
            path
        } else {
            val sep = if (path.startsWith("/")) "" else "/"
            "${config.baseUrl}$sep$path"
        }

    private fun execute(request: HttpRequest): HttpResult {
        val response: HttpResponse<String> = client.send(request, HttpResponse.BodyHandlers.ofString())
        return HttpResult(response.statusCode(), response.headers().map(), response.body())
    }
}
