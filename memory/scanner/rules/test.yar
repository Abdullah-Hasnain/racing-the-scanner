rule rts_secret_marker
{
    meta:
        description = "Finds the harmless Racing-the-Scanner test marker in memory"
        author = "RTS team"
    strings:
        $marker = "RTS_SECRET_MARKER_v1" ascii
    condition:
        $marker
}
