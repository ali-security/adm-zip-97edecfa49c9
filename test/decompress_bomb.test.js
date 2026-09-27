"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// Every public read/extract API funnels into ZipEntry#decompress, so each one is
// an entry point for the declared-size allocation. These tests install a guard on
// Buffer.alloc that refuses any request anywhere near the declared size, which
// makes the check deterministic (no reliance on RSS accounting) and keeps the
// unpatched code from actually committing gigabytes before the test fails.
describe("decompression bomb (declared size) - CVE-2026-39244 - read APIs", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024;
    const MAX_DECLARED = 0xffffffff; // CENLEN/LOCLEN = 0xFFFFFFFF, as in the advisory PoC
    const ALLOC_LIMIT = 64 * 1024 * 1024;
    const target = pth.join(os.tmpdir(), "adm-zip-cve-2026-39244");

    const originalAlloc = Buffer.alloc;
    let largestAlloc = 0;

    function installAllocGuard() {
        largestAlloc = 0;
        Buffer.alloc = function (size) {
            if (size > largestAlloc) largestAlloc = size;
            if (size > ALLOC_LIMIT) {
                throw new Error("Buffer.alloc(" + size + ") sized from the declared entry size");
            }
            return originalAlloc.apply(Buffer, arguments);
        };
    }

    function removeAllocGuard() {
        Buffer.alloc = originalAlloc;
    }

    function guarded(fn) {
        installAllocGuard();
        try {
            return fn();
        } finally {
            removeAllocGuard();
        }
    }

    function captureError(fn) {
        try {
            fn();
        } catch (e) {
            return e;
        }
        return null;
    }

    const storedBomb = (size) => new Zip(craftBomb(size || DECLARED, 0 /* STORED */, Buffer.from("A")));
    // a well-formed deflate stream (so zlib itself succeeds) carrying a wrong crc
    const deflatedBomb = () => new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, zlib.deflateRawSync(Buffer.from("A"))));

    afterEach(() => {
        removeAllocGuard();
        rimraf.sync(target);
    });

    it("entry.getData() does not allocate a 0xFFFFFFFF declared size", () => {
        const zip = storedBomb(MAX_DECLARED);
        const err = guarded(() => captureError(() => zip.getEntries()[0].getData()));
        expect(largestAlloc).to.be.below(ALLOC_LIMIT);
        expect(String(err)).to.match(/CRC32/);
    });

    it("readFile() does not allocate the declared size (STORED)", () => {
        const zip = storedBomb();
        const err = guarded(() => captureError(() => zip.readFile("a")));
        expect(largestAlloc).to.be.below(ALLOC_LIMIT);
        expect(String(err)).to.match(/CRC32/);
    });

    it("readFile() does not allocate the declared size (DEFLATED)", () => {
        const zip = deflatedBomb();
        const err = guarded(() => captureError(() => zip.readFile("a")));
        expect(largestAlloc).to.be.below(ALLOC_LIMIT);
        expect(String(err)).to.match(/CRC32/);
    });

    it("readAsText() does not allocate the declared size", () => {
        const zip = storedBomb();
        const err = guarded(() => captureError(() => zip.readAsText("a")));
        expect(largestAlloc).to.be.below(ALLOC_LIMIT);
        expect(String(err)).to.match(/CRC32/);
    });

    it("test() rejects the archive without allocating the declared size", () => {
        const stored = storedBomb();
        expect(guarded(() => stored.test())).to.equal(false);
        expect(largestAlloc).to.be.below(ALLOC_LIMIT);

        const deflated = deflatedBomb();
        expect(guarded(() => deflated.test())).to.equal(false);
        expect(largestAlloc).to.be.below(ALLOC_LIMIT);
    });

    it("extractEntryTo() does not allocate the declared size", () => {
        const zip = storedBomb();
        const err = guarded(() => captureError(() => zip.extractEntryTo("a", target, false, true)));
        expect(largestAlloc).to.be.below(ALLOC_LIMIT);
        expect(String(err)).to.match(/CRC32/);
    });

    it("extractAllTo() does not allocate the declared size", () => {
        const zip = deflatedBomb();
        const err = guarded(() => captureError(() => zip.extractAllTo(target, true)));
        expect(largestAlloc).to.be.below(ALLOC_LIMIT);
        expect(String(err)).to.match(/CRC32/);
    });

    it("getDataAsync() does not allocate the declared size (STORED)", () => {
        const zip = storedBomb();
        let cbErr = null;
        guarded(() => captureError(() => zip.getEntries()[0].getDataAsync((data, err) => (cbErr = err))));
        expect(largestAlloc).to.be.below(ALLOC_LIMIT);
        expect(String(cbErr)).to.match(/CRC32/);
    });

    it("readFileAsync() does not allocate the declared size (DEFLATED)", (done) => {
        const zip = deflatedBomb();
        installAllocGuard();
        try {
            zip.readFileAsync("a", (data, err) => {
                removeAllocGuard();
                try {
                    expect(largestAlloc).to.be.below(ALLOC_LIMIT);
                    expect(String(err)).to.match(/CRC32/);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        } catch (e) {
            removeAllocGuard();
            done(e);
        }
    });

    it("extractAllToAsync() does not allocate the declared size", (done) => {
        const zip = deflatedBomb();
        installAllocGuard();
        try {
            zip.extractAllToAsync(target, true, false, (err) => {
                removeAllocGuard();
                try {
                    expect(largestAlloc).to.be.below(ALLOC_LIMIT);
                    expect(String(err)).to.match(/CRC32/);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        } catch (e) {
            removeAllocGuard();
            done(e);
        }
    });

    it("still reads a legitimate STORED entry sync and async", (done) => {
        const payload = Buffer.from("stored payload ".repeat(100));
        const zip = new Zip();
        zip.addFile("s.txt", payload);
        zip.getEntry("s.txt").header.method = 0; // force STORED
        const round = new Zip(zip.toBuffer());
        const entry = round.getEntry("s.txt");
        expect(entry.header.method).to.equal(0);
        expect(round.readFile("s.txt").equals(payload)).to.equal(true);
        round.readFileAsync("s.txt", (data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("still reads a legitimate DEFLATED entry async", (done) => {
        const payload = Buffer.from("hello world ".repeat(5000));
        const zip = new Zip();
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        round.readFileAsync("d.txt", (data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });
});
