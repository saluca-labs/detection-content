/*
    gh_vpn_campaigns.yar

    YARA pack for the three Aug-2026 GitHub / VPN campaigns.

      A. BoryptGrab-lineage infostealer  (fake GitHub repos, WinGUP + trojanized libcurl.dll)
      B. QuickFox VPN supply chain       (FDMTP implant, Mustang Panda lineage)
      C. "Free VPN for PC" GitHub repo   (Lumma Stealer dropper)

    Author : Cristian Ruvalcaba and the Saluca Agentic AI Research Team
    Date   : 2026-08-10
    Ref    : README.md

    Scanning notes
      - The loader rules are written for on-disk PE scanning.
      - The BoryptGrab final stealer never touches disk in a normal run. Rule
        BoryptGrab_Stealer_InMemory is intended for process-memory scanning
        (yara -p, EDR memory inspection, or a procdump artifact), not file scanning.
      - Vendor rules from Arctic Wolf live at:
        github.com/rtkwlf/wolf-tools/tree/main/threat-intelligence/
        fake-github-repositories-deliver-boryptgrab-lineage-infostealer/
        Run both. These are written independently against the published behaviour so
        that a vendor rule revision does not silently drop your coverage.
*/

import "pe"
import "hash"

/* ------------------------------------------------------------------ */
/* A. BoryptGrab                                                       */
/* ------------------------------------------------------------------ */

rule BoryptGrab_Loader_libcurl_Sideload
{
    meta:
        description   = "Trojanized libcurl.dll sideloaded by a renamed signed WinGUP gup.exe"
        campaign      = "BoryptGrab-lineage fake GitHub repos"
        reference     = "https://arcticwolf.com/resources/blog/fake-github-repositories-deliver-boryptgrab-lineage-infostealer/"
        author        = "Cristian Ruvalcaba and the Saluca Agentic AI Research Team"
        date          = "2026-08-10"
        severity      = "critical"
        hash_a        = "6db05c4473760c44fa572ffac4c5911b35caf2467a37726c21c5f87e25cb2ea8"
        hash_b        = "fd01262bd56510088b9ddfe58ca101abb98575f3c0259b480a31b917aa73bc56"

    strings:
        // Operator misspelling. Highest-fidelity single string in the family.
        $misspell_1 = "Filegraber" ascii wide
        $misspell_2 = "Operation System" ascii wide

        // Stealer function / log strings carried in the loader's embedded blob region
        $fn_1 = "CreateZipArchive" ascii
        $fn_2 = "SendFileToServer" ascii
        $fn_3 = "KillBrowserProcesses" ascii
        $fn_4 = "ExtractAllCredentials" ascii
        $fn_5 = "CallCOMDecryptData" ascii
        $fn_6 = "GetElevationKey" ascii

        $build = "BUILD NAME:" ascii

    condition:
        uint16(0) == 0x5A4D
        and pe.is_dll()
        and pe.machine == pe.MACHINE_AMD64
        and filesize > 5MB and filesize < 20MB
        and (
              any of ($misspell*)
              or 3 of ($fn*)
              or ($build and any of ($fn*))
        )
}

rule BoryptGrab_Loader_Structural
{
    meta:
        description = "BoryptGrab loader structural profile: PE64 DLL exporting a curl-like surface with no .rsrc and a June-2026 compile stamp"
        campaign    = "BoryptGrab-lineage fake GitHub repos"
        author      = "Cristian Ruvalcaba and the Saluca Agentic AI Research Team"
        date        = "2026-08-10"
        severity    = "high"
        note        = "Lower fidelity than the string rule. Pair with the sideload-path Sigma rule before escalating."

    condition:
        uint16(0) == 0x5A4D
        and pe.is_dll()
        and pe.machine == pe.MACHINE_AMD64
        and pe.image_base == 0x140000000  // reported base for this variant
        // The trojanized build drops .rsrc, which distinguishes it from prior public BoryptGrab
        and not for any i in (0 .. pe.number_of_sections - 1) : (
            pe.sections[i].name == ".rsrc"
        )
        // Non-standard for a real libcurl build: .fptable present
        and for any i in (0 .. pe.number_of_sections - 1) : (
            pe.sections[i].name == ".fptable"
        )
        and pe.timestamp > 1782000000   // 2026-06-20
        and pe.timestamp < 1790000000   // 2026-09-22
        and filesize > 8MB and filesize < 12MB
}

rule BoryptGrab_Stealer_InMemory
{
    meta:
        description = "BoryptGrab final stealer, process-memory scanning only. The payload is never written to disk during normal execution."
        campaign    = "BoryptGrab-lineage fake GitHub repos"
        author      = "Cristian Ruvalcaba and the Saluca Agentic AI Research Team"
        date        = "2026-08-10"
        severity    = "critical"
        scan_target = "process memory"

    strings:
        $banner_1 = "=== Program started ===" ascii
        $banner_2 = "=== Send session ended ===" ascii
        $banner_3 = "=== Version: 1.3 ===" ascii

        $mod_1 = "ExtractSteamData" ascii
        $mod_2 = "ExtractMaxTokens" ascii
        $mod_3 = "CopyTelegramData" ascii
        $mod_4 = "ExtractDiscordTokens" ascii
        $mod_5 = "TakeScreenshot" ascii
        $mod_6 = "KillBrowserProcesses" ascii

        $out_1 = "browser_decryption.log" ascii
        $out_2 = "Discord_tokens.txt" ascii
        $out_3 = "steam_accounts.txt" ascii
        $out_4 = "credentials_data.txt" ascii
        $out_5 = "UserInformation.txt" ascii

        $path_1 = "\\Filegraber" ascii
        $path_2 = "\\Messenger\\Max\\credentials.txt" ascii

        // Hardcoded exfil target
        $c2 = "193.143.1.131" ascii
        $exfil_1 = "POST /upload" ascii
        $exfil_2 = "X-Filename" ascii

    condition:
        any of ($path*)
        or any of ($banner*)
        or ($c2 and any of ($exfil*))
        or 3 of ($mod*)
        or 3 of ($out*)
}

rule BoryptGrab_Delivery_Page
{
    meta:
        description = "Templated gh-downloader fake secure-download page reused across all ~292 impersonated brands"
        campaign    = "BoryptGrab-lineage fake GitHub repos"
        author      = "Cristian Ruvalcaba and the Saluca Agentic AI Research Team"
        date        = "2026-08-10"
        severity    = "high"
        scan_target = "HTML, proxy body capture, crawler output"

    strings:
        $title  = "Github Download" ascii nocase
        $alert  = "Invalid access. Please return to the main page." ascii
        $ru     = "Ð¤ÑƒÐ½ÐºÑ†Ð¸Ñ Ð´Ð»Ñ Ð¿Ñ€ÑÐ¼Ð¾Ð¹ Ð·Ð°Ð³Ñ€ÑƒÐ·ÐºÐ¸ Ð°Ñ€Ñ…Ð¸Ð²Ð°" wide ascii
        $ru_utf8 = { d0 a4 d1 83 d0 bd d0 ba d1 86 d0 b8 d1 8f }  // "Ð¤ÑƒÐ½ÐºÑ†Ð¸Ñ" as UTF-8
        $ep     = "/download-archive?user_code=" ascii
        $domain = "targetroyena.com" ascii nocase

    condition:
        filesize < 2MB
        and (
              $alert
              or $ep
              or $domain
              or ($title and any of ($ru*))
        )
}

rule BoryptGrab_Known_Hashes
{
    meta:
        description = "Exact published BoryptGrab campaign IOC hashes"
        campaign    = "BoryptGrab-lineage fake GitHub repos"
        author      = "Cristian Ruvalcaba and the Saluca Agentic AI Research Team"
        date        = "2026-08-10"
        severity    = "critical"
        note        = "Payloads rotate roughly every 60 seconds, so hash coverage decays fast. Behaviour rules above are the durable control."

    condition:
        hash.sha256(0, filesize) == "1c854a6aa415f4be964e8a4be49c06e092156bf66d71f9c79995b3e6b156e778" or
        hash.sha256(0, filesize) == "6db05c4473760c44fa572ffac4c5911b35caf2467a37726c21c5f87e25cb2ea8" or
        hash.sha256(0, filesize) == "fd01262bd56510088b9ddfe58ca101abb98575f3c0259b480a31b917aa73bc56" or
        hash.sha256(0, filesize) == "07dcc12197490bf3292619273ba8b11a960273a34265bca3b7d6d40e8c47dc82" or
        hash.sha256(0, filesize) == "8e1ea6d9a8ccb303be9a2aad3524a529d0d99b1b24a136d8422276e942c4c4b8" or
        hash.sha256(0, filesize) == "e9a56961980031a45e578472836576da874512bff50ca3d491fc72e52f7cc7c2" or
        hash.sha256(0, filesize) == "52825dbf3fc28b9f7c3a24adf78d3425ac714e975769f4d70e8c718ddcbb9856"
}

/* ------------------------------------------------------------------ */
/* B. QuickFox / FDMTP                                                 */
/* ------------------------------------------------------------------ */

rule QuickFox_FDMTP_Loader_Gen2
{
    meta:
        description = "FDMTP Gen2 .NET loader: JieJie-obfuscated, decrypts update.bin with a hardcoded AES-128-ECB key"
        campaign    = "QuickFox VPN supply chain"
        reference   = "https://www.fortinet.com/blog/threat-research/quickfox-supply-chain-attack-used-to-deploy-fdmtp-implant"
        author      = "Cristian Ruvalcaba and the Saluca Agentic AI Research Team"
        date        = "2026-08-10"
        severity    = "critical"
        hash_gen2   = "795594ad5e6f2868cc4d8ed12dabf4f3999a1477c6b250527c5ede9a98528fb9"

    strings:
        // Hardcoded AES-128-ECB key for update.bin. Single highest-value string in this family.
        $key    = "POt_L[Bsh0=+@0a." ascii wide

        $bin    = "update.bin" ascii wide
        $jiejie = "JieJie" ascii wide
        $client = "Client.FDMTPFrame" ascii wide
        $dev    = "DevStore" ascii wide
        $proto  = "DotNet-TcpFDMTP" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and (
              $key
              or $proto
              or $client
              or ($bin and $jiejie)
              or ($bin and $dev)
        )
}

rule QuickFox_FDMTP_Registration
{
    meta:
        description = "FDMTP cluster registration protocol strings and staging domains"
        campaign    = "QuickFox VPN supply chain"
        author      = "Cristian Ruvalcaba and the Saluca Agentic AI Research Team"
        date        = "2026-08-10"
        severity    = "critical"
        scan_target = "PE, process memory, decrypted config"

    strings:
        $proto = "DotNet-TcpFDMTP" ascii wide

        $ep_1 = "/GetCluster?protocol=" ascii wide
        $ep_2 = "GetSlaver" ascii wide
        $ep_3 = "GetGateways" ascii wide
        $ep_4 = "GetEndpoints" ascii wide

        $d_1 = "icloud-cdn.net" ascii wide nocase
        $d_2 = "google-apis.net" ascii wide nocase
        $d_3 = "yahoo-cdn.it.com" ascii wide nocase
        $d_4 = "wangmeng.xyz" ascii wide nocase
        $d_5 = "wangmengsb.com" ascii wide nocase
        $d_6 = "wangmeng66.top" ascii wide nocase
        $d_7 = "techcheck1.com" ascii wide nocase
        $d_8 = "cdns3.51quickfox.cn" ascii wide nocase

    condition:
        $proto
        or ($ep_1 and any of ($d_*))
        or 2 of ($d_*)
        or ($d_8)
        or (2 of ($ep_*) and any of ($d_*))
}

rule QuickFox_Trojanized_Renderer
{
    meta:
        description = "QuickFox Electron renderer index.html with injected remote loader fetch"
        campaign    = "QuickFox VPN supply chain"
        author      = "Cristian Ruvalcaba and the Saluca Agentic AI Research Team"
        date        = "2026-08-10"
        severity    = "critical"
        scan_target = "extracted app.asar contents, installer staging dirs"
        note        = "Injected into resources/app.asar/candy/core/service/index.html"

    strings:
        $host  = "cdns3.51quickfox.cn" ascii nocase
        $js_1  = "firebase-app-compat.js" ascii nocase
        $js_2  = "firebase-analytics-compat.js" ascii nocase
        $zip   = "update.zip" ascii nocase
        $candy = "candy/core/service" ascii nocase

    condition:
        filesize < 5MB
        and (
              $host
              or ($js_1 and $candy)
              or ($js_1 and $js_2 and $zip)
        )
}

rule QuickFox_FDMTP_Known_Hashes
{
    meta:
        description = "Exact published FDMTP loader hashes"
        campaign    = "QuickFox VPN supply chain"
        author      = "Cristian Ruvalcaba and the Saluca Agentic AI Research Team"
        date        = "2026-08-10"
        severity    = "critical"

    condition:
        hash.sha256(0, filesize) == "2b6cdafdfe427a3de1a94a8a2ca1f09fc4c8f90e4f59089fd9b35b73185ed01c" or
        hash.sha256(0, filesize) == "795594ad5e6f2868cc4d8ed12dabf4f3999a1477c6b250527c5ede9a98528fb9"
}

/* ------------------------------------------------------------------ */
/* C. "Free VPN for PC" / Lumma                                        */
/* ------------------------------------------------------------------ */

rule LummaVPN_Dropper_Launch
{
    meta:
        description = "Launch.exe dropper from the SAMAIOEC free-vpn-for-pc / minecraft-skin GitHub repos"
        campaign    = "Free VPN for PC GitHub repo, Lumma Stealer"
        reference   = "https://www.cyfirma.com/research/github-abused-to-spread-malware-disguised-as-free-vpn/"
        author      = "Cristian Ruvalcaba and the Saluca Agentic AI Research Team"
        date        = "2026-08-10"
        severity    = "critical"
        hash_sha256 = "acbaa6041286f9e3c815cd1712771a490530f52c90ce64da20f28cfa0955a5ca"
        hash_md5    = "bbc7fc957d4fff6a55bd004a3d124dda"

    strings:
        // Staged with a .dqq extension, then renamed to .dll
        $stage_1 = "msvcp110.dqq" ascii wide
        $stage_2 = "msvcp110.dll" ascii wide

        // Export invoked from the dropped DLL
        $export = "GetGameData" ascii wide

        // Manual-map / injection API surface
        $api_1 = "NtWriteVirtualMemory" ascii
        $api_2 = "NtCreateThreadEx" ascii
        $api_3 = "VirtualAlloc" ascii
        $api_4 = "GetProcAddress" ascii

        // Injection targets
        $inj_1 = "MSBuild.exe" ascii wide nocase
        $inj_2 = "aspnet_regiis.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D
        and (
              $stage_1
              or ($export and $stage_2)
              or ($export and 2 of ($api*))
              or (any of ($inj*) and $api_2 and $api_1)
        )
}

rule LummaVPN_Known_Hashes
{
    meta:
        description = "Exact published hashes for the Free VPN for PC Lumma chain"
        campaign    = "Free VPN for PC GitHub repo, Lumma Stealer"
        author      = "Cristian Ruvalcaba and the Saluca Agentic AI Research Team"
        date        = "2026-08-10"
        severity    = "critical"

    condition:
        hash.sha256(0, filesize) == "acbaa6041286f9e3c815cd1712771a490530f52c90ce64da20f28cfa0955a5ca" or
        hash.sha256(0, filesize) == "15b644b42edce646e8ba69a677edcb09ec752e6e7920fd982979c714aece3925"
}

/* ------------------------------------------------------------------ */
/* Cross-campaign                                                      */
/* ------------------------------------------------------------------ */

rule GhVpn_Campaign_C2_Domains
{
    meta:
        description = "Any campaign C2 or distribution domain embedded in a sample, config, or memory image"
        campaign    = "all three"
        author      = "Cristian Ruvalcaba and the Saluca Agentic AI Research Team"
        date        = "2026-08-10"
        severity    = "high"

    strings:
        // A - distribution / TDS
        $a1  = "targetroyena.com"  ascii wide nocase
        $a2  = "furiesniffer.com"  ascii wide nocase
        $a3  = "fleecykobird.com"  ascii wide nocase
        $a4  = "balafohoaxee.com"  ascii wide nocase
        $a5  = "yontzarpzenu.com"  ascii wide nocase
        $a6  = "eggcupmadras.com"  ascii wide nocase
        $a7  = "lafferdingar.com"  ascii wide nocase
        $a8  = "palchknosp.com"    ascii wide nocase
        $a9  = "brakerhotdog.com"  ascii wide nocase
        $a10 = "sellietuskar.com"  ascii wide nocase
        $a11 = "logic-prox.com"    ascii wide nocase
        $a12 = "hamletlunoid.com"  ascii wide nocase
        $a13 = "parnelmentha.com"  ascii wide nocase
        $a14 = "refonttaught.com"  ascii wide nocase

        // C - Lumma
        $c1 = "explorationmsn.store" ascii wide nocase
        $c2 = "snailyeductyi.sbs"    ascii wide nocase
        $c3 = "ferrycheatyk.sbs"     ascii wide nocase
        $c4 = "deepymouthi.sbs"      ascii wide nocase
        $c5 = "wrigglesight.sbs"     ascii wide nocase
        $c6 = "captaitwik.sbs"       ascii wide nocase
        $c7 = "sidercotay.sbs"       ascii wide nocase
        $c8 = "heroicmint.sbs"       ascii wide nocase
        $c9 = "monstourtu.sbs"       ascii wide nocase

    condition:
        any of them
}
