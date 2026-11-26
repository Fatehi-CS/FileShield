const StaticFeatureExtractor = {
    suspiciousAPIs: [
        "powershell", "cmd.exe", "eval(", "exec(", "base64_decode",
        "createremotethread", "virtualalloc", "writeprocessmemory",
        "wscript.shell", "regwrite", "downloadfile", "invoke-expression",
        "chmod +x", "/bin/sh", "autoopen", "shellexecute", "urldownloadtofile"
    ],

    async computeSHA256(buffer) {
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        return Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    },

    computeShannonEntropy(bytes) {
        if (!bytes.length) return 0;
        const freq = new Array(256).fill(0);
        for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
        let entropy = 0;
        for (let i = 0; i < 256; i++) {
            if (freq[i] > 0) {
                const p = freq[i] / bytes.length;
                entropy -= p * Math.log2(p);
            }
        }
        return entropy;
    },

    inspectMagicBytes(bytes, fileName) {
        const ext = fileName.split('.').pop().toLowerCase();
        const b0 = bytes.at(0), b1 = bytes.at(1), b2 = bytes.at(2), b3 = bytes.at(3);
        let realType = "Generic / Text / Data";
        let isExec = 0;
        let isSpoofed = false;

        if (bytes.length >= 2 && b0 === 0x4D && b1 === 0x5A) {
            realType = "Windows Executable (PE/EXE/DLL)";
            isExec = 1;
            if (!["exe", "dll", "sys", "scr"].includes(ext)) isSpoofed = true;
        } else if (bytes.length >= 4 && b0 === 0x7F && b1 === 0x45 && b2 === 0x4C && b3 === 0x46) {
            realType = "Linux Executable (ELF)";
            isExec = 1;
            if (["pdf", "jpg", "png", "txt", "mp4"].includes(ext)) isSpoofed = true;
        } else if (bytes.length >= 4 && b0 === 0x50 && b1 === 0x4B && b2 === 0x03 && b3 === 0x04) {
            realType = "ZIP / Android APK / Office OpenXML";
            isExec = 0.4;
        } else if (bytes.length >= 4 && b0 === 0x25 && b1 === 0x50 && b2 === 0x44 && b3 === 0x46) {
            realType = "PDF Document";
            isExec = 0.1;
        }

        return { realType, isExec, isSpoofed };
    },

    async extractAll(file) {
        const buffer = await file.arrayBuffer();
        const bytes = new Uint8Array(buffer);
        const sha256 = await this.computeSHA256(buffer);
        const entropy = this.computeShannonEntropy(bytes);
        const sig = this.inspectMagicBytes(bytes, file.name);

        let nonAscii = 0;
        for (let i = 0; i < bytes.length; i++) {
            if (bytes[i] < 32 || bytes[i] > 126) nonAscii++;
        }
        const nonAsciiRatio = bytes.length ? (nonAscii / bytes.length) : 0;

        const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        const lowerText = text.toLowerCase();
        const matchedAPIs = this.suspiciousAPIs.filter(api => lowerText.includes(api));

        const urlRegex = /https?:\/\/[^\s"'<>]+/gi;
        const embeddedURLs = [...new Set(text.match(urlRegex) || [])].slice(0, 5);

        return {
            fileName: file.name,
            sizeKB: (file.size / 1024).toFixed(2),
            sha256,
            entropy,
            realType: sig.realType,
            isExec: sig.isExec,
            isSpoofed: sig.isSpoofed,
            nonAsciiRatio,
            matchedAPIs,
            embeddedURLs
        };
    }
};
