rule ONION_MALWARE_1 {
   meta:
      description = "Fake rule"
      license = "None"
      author = "Security Onion Solutions"
      reference = "https://goo.gl/WVflzO"
      date = "2024-08-28"
      hash1 = "9acab7e5f972cdd722541a23aa314ea81ac54d5c0c758eb708fb6e2cc4f598a0"
      hash2 = "56558d3427ce932d8ffcbe54dccf97c9a8a2e85c767814e34b3b2b6a6b305641"
   strings:
      $x1 = "Onion_malware.dll" fullword ascii

      $s1 = "CrashErrors" fullword ascii
      $s2 = "CrashSend" fullword ascii
      $s3 = "CrashAddData" fullword ascii
      $s4 = "CrashCleanup" fullword ascii
      $s5 = "CrashInit" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and $x1 ) or ( all of them )
}
