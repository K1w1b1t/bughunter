fun main(args: Array<String>) {
    val target = if (args.isNotEmpty()) args[0] else ""
    val hint = when {
        target.contains("admin") -> 90
        target.contains("api") -> 60
        else -> 25
    }
    println("""{"module":"kotlin_role_diff","target":"$target","hint":$hint}""")
}
