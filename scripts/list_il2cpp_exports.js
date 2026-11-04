// list_il2cpp_exports.js
//
// Doesn't hook anything - just enumerates the exports (and symbols, if any)
// of the app's IL2CPP module (the profile's `module`; there is no default) to
// find the real name of il2cpp_init in the current build. Build this with
// `npm run build` and run the bundled dist/list_il2cpp_exports.js through
// retk exports - see docs/INSTALL.md. It
// needs only `module` from rpc.exports.init(stage, params).

import { waitForModule, parseParams, agentInit } from "./_lib.js";

function scan(mod) {
    console.log("[+]", mod.name, "base =", mod.base, " size =", mod.size);

    const exports = mod.enumerateExports();
    console.log("[+] Total exports:", exports.length);

    let matches = exports.filter((e) => e.name.toLowerCase().includes("il2cpp_init"));
    console.log("[+] Exports containing 'il2cpp_init':", JSON.stringify(matches, null, 2));

    if (matches.length === 0) {
        const broader = exports
            .filter((e) => e.name.toLowerCase().includes("il2cpp"))
            .slice(0, 80);
        console.log("[+] No match containing 'il2cpp_init'. First 80 exports containing 'il2cpp':");
        console.log(JSON.stringify(broader, null, 2));
    }

    // Also try enumerateSymbols - may not be available if the binary has
    // its local symbol table fully stripped, but global exports usually
    // survive.
    try {
        const syms = mod.enumerateSymbols();
        console.log("[+] enumerateSymbols available, total:", syms.length);
        const symMatch = syms
            .filter((s) => s.name.toLowerCase().includes("il2cpp_init"))
            .slice(0, 20);
        console.log("[+] Symbols matching 'il2cpp_init':", JSON.stringify(symMatch, null, 2));
    } catch (e) {
        console.log("[!] enumerateSymbols not available here:", e.message);
    }

    console.log("[+] Scan complete. Script can exit now.");
    if (typeof send === "function") {
        send({ event: "scan-complete" });
    }
}

rpc.exports = {
    init: agentInit((params) => {
        const p = parseParams(params);
        waitForModule(p.moduleName, scan);
    }),
};
