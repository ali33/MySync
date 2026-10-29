// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/index.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <thread>
#include <unordered_set>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

#include "mysync/hash.h"

namespace fs = std::filesystem;

namespace mysync {
namespace {

constexpr char kMagic[4] = {'M', 'S', 'I', 'X'};
constexpr uint32_t kVersion = 1;
constexpr uint64_t kMaxIndexFile = 1ull << 30;  // refuse to slurp anything bigger
constexpr int64_t kRacyWindowNs = 2'000'000'000LL;

// ---------------------------------------------------------------- binary helpers

void put_u16(Bytes& b, uint16_t v) { b.push_back(static_cast<uint8_t>(v >> 8)); b.push_back(static_cast<uint8_t>(v)); }
void put_u32(Bytes& b, uint32_t v) { for (int i = 3; i >= 0; --i) b.push_back(static_cast<uint8_t>(v >> (8 * i))); }
void put_u64(Bytes& b, uint64_t v) { for (int i = 7; i >= 0; --i) b.push_back(static_cast<uint8_t>(v >> (8 * i))); }

struct Reader {
    const uint8_t* p;
    size_t n;
    size_t pos = 0;
    bool ok = true;
    bool need(size_t k) {
        if (!ok || n - pos < k) { ok = false; return false; }
        return true;
    }
    uint8_t u8() { return need(1) ? p[pos++] : 0; }
    uint16_t u16() { uint16_t v = 0; if (need(2)) { v = static_cast<uint16_t>(p[pos] << 8 | p[pos + 1]); pos += 2; } return v; }
    uint32_t u32() { uint32_t v = 0; if (need(4)) { for (int i = 0; i < 4; ++i) v = v << 8 | p[pos + static_cast<size_t>(i)]; pos += 4; } return v; }
    uint64_t u64() { uint64_t v = 0; if (need(8)) { for (int i = 0; i < 8; ++i) v = v << 8 | p[pos + static_cast<size_t>(i)]; pos += 8; } return v; }
    std::string str(size_t len) {
        if (!need(len)) return {};
        std::string s(reinterpret_cast<const char*>(p + pos), len);
        pos += len;
        return s;
    }
};

// ---------------------------------------------------------------- file system access

struct StatInfo {
    bool ok = false;
    bool is_dir = false;
    bool is_file = false;
    bool is_link = false;  // symlink / junction: never followed
    uint64_t size = 0;
    int64_t mtime_ns = 0;
};

StatInfo stat_path(const fs::path& p) {
    StatInfo si;
#ifdef _WIN32
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(p.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return si;
    FindClose(h);
    si.ok = true;
    bool reparse = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    si.is_link = reparse && (fd.dwReserved0 == IO_REPARSE_TAG_SYMLINK || fd.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT);
    si.is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    si.is_file = !si.is_dir && !si.is_link && (fd.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) == 0;
    si.size = (static_cast<uint64_t>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
    uint64_t ft = (static_cast<uint64_t>(fd.ftLastWriteTime.dwHighDateTime) << 32) | fd.ftLastWriteTime.dwLowDateTime;
    si.mtime_ns = (static_cast<int64_t>(ft) - 116444736000000000LL) * 100;
#else
    struct stat st;
    if (::lstat(p.c_str(), &st) != 0) return si;
    si.ok = true;
    si.is_link = S_ISLNK(st.st_mode);
    si.is_dir = S_ISDIR(st.st_mode);
    si.is_file = S_ISREG(st.st_mode);
    si.size = static_cast<uint64_t>(st.st_size);
#ifdef __APPLE__
    si.mtime_ns = static_cast<int64_t>(st.st_mtimespec.tv_sec) * 1000000000LL + st.st_mtimespec.tv_nsec;
#else
    si.mtime_ns = static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;
#endif
#endif
    return si;
}

bool valid_utf8(const std::string& s) {
    size_t i = 0, n = s.size();
    while (i < n) {
        uint8_t c = static_cast<uint8_t>(s[i]);
        size_t len = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
        if (len == 0 || i + len > n) return false;
        for (size_t k = 1; k < len; ++k)
            if ((static_cast<uint8_t>(s[i + k]) & 0xC0) != 0x80) return false;
        if (len == 2 && c < 0xC2) return false;
        i += len;
    }
    return true;
}

} // namespace

// ---------------------------------------------------------------- IndexCache

bool IndexCache::load(const std::string& utf8_path) {
    map_.clear();
    try {
        std::ifstream f(fs::u8path(utf8_path), std::ios::binary | std::ios::ate);
        if (!f) return false;
        std::streamoff sz = f.tellg();
        if (sz < 0 || static_cast<uint64_t>(sz) > kMaxIndexFile || sz < 4 + 4 + 8 + 32) return false;
        Bytes buf(static_cast<size_t>(sz));
        f.seekg(0);
        f.read(reinterpret_cast<char*>(buf.data()), sz);
        if (!f) return false;

        size_t body = buf.size() - 32;
        Hash256 want = hash_bytes(buf.data(), body);
        if (!ct_equal(want.data(), buf.data() + body, 32)) return false;

        Reader r{buf.data(), body};
        if (std::memcmp(r.p, kMagic, 4) != 0) return false;
        r.pos = 4;
        if (r.u32() != kVersion) return false;
        uint64_t count = r.u64();
        // every entry needs at least 2 + 1 + 8 + 8 + 1 + 32 bytes: reject absurd counts before looping
        if (!r.ok || count > (body - r.pos) / 52) return false;
        std::map<std::string, FileMeta> tmp;
        for (uint64_t i = 0; i < count; ++i) {
            FileMeta m;
            uint16_t len = r.u16();
            m.rel = r.str(len);
            m.size = r.u64();
            m.mtime_ns = static_cast<int64_t>(r.u64());
            m.is_dir = r.u8() != 0;
            if (r.need(32)) {
                std::memcpy(m.hash.data(), r.p + r.pos, 32);
                r.pos += 32;
            }
            if (!r.ok || m.rel.empty()) return false;
            tmp[m.rel] = std::move(m);
        }
        if (r.pos != body) return false;
        map_ = std::move(tmp);
        return true;
    } catch (...) {
        map_.clear();
        return false;
    }
}

void IndexCache::save(const std::string& utf8_path) const {
    Bytes b;
    b.insert(b.end(), kMagic, kMagic + 4);
    put_u32(b, kVersion);
    put_u64(b, map_.size());
    for (const auto& kv : map_) {
        const FileMeta& m = kv.second;
        if (m.rel.size() > 0xFFFF) throw Error("index: path too long");
        put_u16(b, static_cast<uint16_t>(m.rel.size()));
        b.insert(b.end(), m.rel.begin(), m.rel.end());
        put_u64(b, m.size);
        put_u64(b, static_cast<uint64_t>(m.mtime_ns));
        b.push_back(m.is_dir ? 1 : 0);
        b.insert(b.end(), m.hash.begin(), m.hash.end());
    }
    Hash256 sum = hash_bytes(b.data(), b.size());
    b.insert(b.end(), sum.begin(), sum.end());

    fs::path target = fs::u8path(utf8_path);
    fs::path tmp = target;
    tmp += ".tmp";
    std::error_code ec;
    if (target.has_parent_path()) fs::create_directories(target.parent_path(), ec);
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) throw Error("cannot write index file: " + utf8_path);
        f.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
        f.flush();
        if (!f) {
            f.close();
            fs::remove(tmp, ec);
            throw Error("failed writing index file: " + utf8_path);
        }
    }
    fs::rename(tmp, target, ec);
    if (ec) {
        std::error_code ec2;
        fs::remove(tmp, ec2);
        throw Error("cannot replace index file " + utf8_path + ": " + ec.message());
    }
}

const FileMeta* IndexCache::find(const std::string& rel) const {
    auto it = map_.find(rel);
    return it == map_.end() ? nullptr : &it->second;
}

void IndexCache::put(const FileMeta& m) { map_[m.rel] = m; }

bool IndexCache::erase(const std::string& rel) { return map_.erase(rel) != 0; }

size_t IndexCache::rename_prefix(const std::string& from, const std::string& to) {
    if (from.empty() || from == to) return 0;
    std::vector<FileMeta> moved;
    auto it = map_.find(from);
    if (it != map_.end()) {
        moved.push_back(std::move(it->second));
        map_.erase(it);
    }
    std::string pre = from + "/";
    auto lo = map_.lower_bound(pre);
    while (lo != map_.end() && lo->first.compare(0, pre.size(), pre) == 0) {
        moved.push_back(std::move(lo->second));
        lo = map_.erase(lo);
    }
    for (auto& m : moved) {
        m.rel = to + m.rel.substr(from.size());
        map_[m.rel] = std::move(m);
    }
    return moved.size();
}

// ---------------------------------------------------------------- scan_tree

std::vector<FileMeta> scan_tree(const std::string& root_utf8, const Filter& filter, IndexCache& cache,
                                unsigned threads, ScanStats* stats) {
    ScanStats st;
    fs::path root = fs::u8path(root_utf8);
    {
        std::error_code ec;
        if (!fs::is_directory(root, ec)) throw Error("scan root is not a directory: " + root_utf8);
    }
    const int64_t racy_before = now_unix_ns() - kRacyWindowNs;

    struct Job { size_t out_index; bool cacheable; };
    std::vector<FileMeta> out;
    std::vector<Job> jobs;
    std::unordered_set<std::string> seen;
    std::vector<std::string> failed_dirs;

    struct Dir { fs::path abs; std::string rel; };
    std::vector<Dir> stack;
    stack.push_back({root, std::string()});
    while (!stack.empty()) {
        Dir d = std::move(stack.back());
        stack.pop_back();
        std::error_code ec;
        fs::directory_iterator it(d.abs, ec), end;
        if (ec) {
            log_warn("scan: cannot read directory " + (d.rel.empty() ? root_utf8 : d.rel) + ": " + ec.message());
            failed_dirs.push_back(d.rel);
            ++st.failed;
            continue;
        }
        for (; it != end; it.increment(ec)) {
            if (ec) break;
            const fs::path& child = it->path();
            std::string name = child.filename().u8string();
            std::string rel = d.rel.empty() ? name : d.rel + "/" + name;
            if (!valid_utf8(name)) {
                log_warn("scan: skipping entry with invalid UTF-8 name under " + (d.rel.empty() ? "." : d.rel));
                ++st.failed;
                continue;
            }
            StatInfo si = stat_path(child);
            if (!si.ok) {
                log_warn("scan: cannot stat " + rel);
                ++st.failed;
                continue;
            }
            if (si.is_link) continue;
            if (si.is_dir) {
                if (!filter.match_dir(rel)) continue;
                stack.push_back({child, rel});
                if (filter.includes_all()) {
                    FileMeta m;
                    m.rel = rel;
                    m.mtime_ns = si.mtime_ns;
                    m.is_dir = true;
                    out.push_back(std::move(m));
                }
                continue;
            }
            if (!si.is_file) continue;
            if (!filter.match(rel, si.size, si.mtime_ns)) continue;
            seen.insert(rel);
            const FileMeta* c = cache.find(rel);
            bool fresh = si.mtime_ns < racy_before;
            if (c && !c->is_dir && fresh && c->size == si.size && c->mtime_ns == si.mtime_ns) {
                out.push_back(*c);
                ++st.reused;
                continue;
            }
            FileMeta m;
            m.rel = rel;
            m.size = si.size;
            m.mtime_ns = si.mtime_ns;
            jobs.push_back({out.size(), fresh});
            out.push_back(std::move(m));
        }
        if (ec) {
            log_warn("scan: error while listing " + (d.rel.empty() ? root_utf8 : d.rel) + ": " + ec.message());
            failed_dirs.push_back(d.rel);
            ++st.failed;
        }
    }

    // hash the changed files in parallel
    std::vector<char> done(jobs.size(), 0);
    if (!jobs.empty()) {
        unsigned n = threads ? threads : std::max(1u, std::thread::hardware_concurrency());
        n = std::min<unsigned>(n, static_cast<unsigned>(jobs.size()));
        std::atomic<size_t> next{0};
        auto worker = [&]() {
            for (;;) {
                size_t k = next.fetch_add(1);
                if (k >= jobs.size()) return;
                FileMeta& m = out[jobs[k].out_index];
                try {
                    uint64_t sz = 0;
                    m.hash = hash_file(root_utf8 + "/" + m.rel, &sz);
                    m.size = sz;
                    done[k] = 1;
                } catch (const std::exception&) {
                    done[k] = 0;
                }
            }
        };
        std::vector<std::thread> pool;
        for (unsigned i = 1; i < n; ++i) pool.emplace_back(worker);
        worker();
        for (auto& t : pool) t.join();
    }

    std::vector<bool> drop(out.size(), false);
    for (size_t k = 0; k < jobs.size(); ++k) {
        FileMeta& m = out[jobs[k].out_index];
        if (!done[k]) {
            log_warn("scan: cannot read " + m.rel + ", skipped");
            ++st.failed;
            drop[jobs[k].out_index] = true;
            continue;
        }
        ++st.hashed;
        st.bytes_hashed += m.size;
        if (jobs[k].cacheable) cache.put(m);
        else cache.erase(m.rel);
    }

    // forget files that disappeared (but not those under directories we failed to list)
    std::vector<std::string> gone;
    for (const auto& kv : cache.entries()) {
        if (seen.count(kv.first)) continue;
        bool protectedd = false;
        for (const auto& fd : failed_dirs)
            if (fd.empty() || kv.first.compare(0, fd.size() + 1, fd + "/") == 0) { protectedd = true; break; }
        if (!protectedd) gone.push_back(kv.first);
    }
    for (const auto& g : gone) cache.erase(g);

    std::vector<FileMeta> result;
    result.reserve(out.size());
    for (size_t i = 0; i < out.size(); ++i)
        if (!drop[i]) result.push_back(std::move(out[i]));
    std::sort(result.begin(), result.end(), [](const FileMeta& a, const FileMeta& b) { return a.rel < b.rel; });
    for (const auto& m : result)
        if (!m.is_dir) ++st.files;
    if (stats) *stats = st;
    return result;
}

} // namespace mysync
