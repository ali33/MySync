// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/simple/user_engine.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <thread>

#include "mysync/engine_lock.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;
#endif

namespace fs = std::filesystem;

namespace mysync::simple {

const char* engine_state_name(EngineState s) {
    switch (s) {
        case EngineState::Stopped: return "stopped";
        case EngineState::Starting: return "starting";
        case EngineState::Running: return "running";
        case EngineState::Backoff: return "backoff";
        case EngineState::GaveUp: return "gave-up";
    }
    return "?";
}

namespace {

int64_t steady_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

std::string self_exe_path() {
#ifdef _WIN32
    std::wstring buf(1024, L'\0');
    for (;;) {
        DWORD n = GetModuleFileNameW(nullptr, &buf[0], static_cast<DWORD>(buf.size()));
        if (n == 0) return {};
        if (n < buf.size()) { buf.resize(n); break; }
        buf.resize(buf.size() * 2);
    }
    return fs::path(buf).u8string();
#else
    std::error_code ec;
    fs::path p = fs::read_symlink("/proc/self/exe", ec);
    return ec ? std::string() : p.string();
#endif
}

// -------------------------------------------------------------------------------------------- child process
struct Proc {
#ifdef _WIN32
    HANDLE hproc = nullptr;
    HANDLE hout = nullptr;  // read end of the child's stdout+stderr
    HANDLE hin = nullptr;   // write end of the child's stdin (closing it asks the engine to stop)
    DWORD pid = 0;
#else
    pid_t pid = -1;
    int out_fd = -1;
    int in_fd = -1;
#endif
    std::thread reader;
    std::mutex m;
    std::string tail;  // last bytes of the output (bounded)

    ~Proc() { release(); }

    void close_stdin() {
#ifdef _WIN32
        if (hin) { CloseHandle(hin); hin = nullptr; }
#else
        if (in_fd >= 0) { ::close(in_fd); in_fd = -1; }
#endif
    }
    // After the process is gone: join the reader, close handles.
    void release() {
        close_stdin();
#ifdef _WIN32
        if (hproc) { WaitForSingleObject(hproc, 2000); }
        if (reader.joinable()) reader.join();
        if (hout) { CloseHandle(hout); hout = nullptr; }
        if (hproc) { CloseHandle(hproc); hproc = nullptr; }
#else
        if (reader.joinable()) reader.join();
        if (out_fd >= 0) { ::close(out_fd); out_fd = -1; }
#endif
    }
    void add_output(const char* d, size_t n) {
        std::lock_guard<std::mutex> lk(m);
        tail.append(d, n);
        if (tail.size() > 8192) tail.erase(0, tail.size() - 8192);
    }
    std::string last_lines(size_t max_lines = 12) {
        std::string t;
        {
            std::lock_guard<std::mutex> lk(m);
            t = tail;
        }
        std::vector<std::string> lines;
        std::string cur;
        for (char c : t) {
            if (c == '\n') { if (!cur.empty()) lines.push_back(cur); cur.clear(); }
            else if (c != '\r' && static_cast<unsigned char>(c) >= 0x09) cur += c;
        }
        if (!cur.empty()) lines.push_back(cur);
        std::string out;
        size_t from = lines.size() > max_lines ? lines.size() - max_lines : 0;
        for (size_t i = from; i < lines.size(); ++i) out += (out.empty() ? "" : "\n") + lines[i];
        return out;
    }
};

#ifdef _WIN32
std::wstring quote_arg(const std::wstring& a) {
    // CommandLineToArgvW rules.
    if (!a.empty() && a.find_first_of(L" \t\n\v\"") == std::wstring::npos) return a;
    std::wstring r = L"\"";
    for (size_t i = 0;; ++i) {
        size_t bs = 0;
        while (i < a.size() && a[i] == L'\\') { ++bs; ++i; }
        if (i == a.size()) { r.append(bs * 2, L'\\'); break; }
        if (a[i] == L'"') { r.append(bs * 2 + 1, L'\\'); r += L'"'; }
        else { r.append(bs, L'\\'); r += a[i]; }
    }
    return r + L"\"";
}

HANDLE job_handle() {
    static HANDLE job = [] {
        HANDLE h = CreateJobObjectW(nullptr, nullptr);
        if (!h) return HANDLE(nullptr);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION li{};
        li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(h, JobObjectExtendedLimitInformation, &li, sizeof li);
        return h;  // never closed: it ends with the GUI, which kills the engines
    }();
    return job;
}

std::unique_ptr<Proc> spawn_proc(const std::string& exe, const std::vector<std::string>& args, const std::string& cwd) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    HANDLE out_r = nullptr, out_w = nullptr, in_r = nullptr, in_w = nullptr;
    if (!CreatePipe(&out_r, &out_w, &sa, 0)) throw Error("cannot create a pipe for the engine");
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    if (!CreatePipe(&in_r, &in_w, &sa, 0)) {
        CloseHandle(out_r); CloseHandle(out_w);
        throw Error("cannot create a pipe for the engine");
    }
    SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);

    std::wstring cmd = quote_arg(fs::u8path(exe).wstring());
    for (const std::string& a : args) cmd += L" " + quote_arg(fs::u8path(a).wstring());
    std::vector<wchar_t> cmdbuf(cmd.begin(), cmd.end());
    cmdbuf.push_back(0);

    SIZE_T sz = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &sz);
    std::vector<char> attr(sz);
    auto* al = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr.data());
    HANDLE inherit[2] = {in_r, out_w};
    bool al_ok = InitializeProcThreadAttributeList(al, 1, 0, &sz) &&
                 UpdateProcThreadAttribute(al, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit, sizeof inherit, nullptr, nullptr);
    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof si;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = in_r;
    si.StartupInfo.hStdOutput = out_w;
    si.StartupInfo.hStdError = out_w;
    si.lpAttributeList = al_ok ? al : nullptr;
    PROCESS_INFORMATION pi{};
    std::wstring wcwd = fs::u8path(cwd).wstring();
    BOOL ok = CreateProcessW(fs::u8path(exe).c_str(), cmdbuf.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW | CREATE_SUSPENDED | (al_ok ? EXTENDED_STARTUPINFO_PRESENT : 0), nullptr,
                             cwd.empty() ? nullptr : wcwd.c_str(), &si.StartupInfo, &pi);
    DWORD err = GetLastError();
    if (al_ok) DeleteProcThreadAttributeList(al);
    CloseHandle(out_w);
    CloseHandle(in_r);
    if (!ok) {
        CloseHandle(out_r);
        CloseHandle(in_w);
        throw Error("cannot start '" + exe + "' (error " + std::to_string(err) + ")");
    }
    if (HANDLE job = job_handle()) {
        if (!AssignProcessToJobObject(job, pi.hProcess))
            log_warn("the engine could not be placed in the job object: it will not die with the window if that is killed");
    }
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    auto p = std::make_unique<Proc>();
    p->hproc = pi.hProcess;
    p->pid = pi.dwProcessId;
    p->hout = out_r;
    p->hin = in_w;
    Proc* raw = p.get();
    p->reader = std::thread([raw] {
        char buf[1024];
        DWORD n = 0;
        while (ReadFile(raw->hout, buf, sizeof buf, &n, nullptr) && n > 0) raw->add_output(buf, n);
    });
    return p;
}

bool proc_exited(Proc& p, int* code) {
    if (WaitForSingleObject(p.hproc, 0) != WAIT_OBJECT_0) return false;
    DWORD c = 0;
    GetExitCodeProcess(p.hproc, &c);
    *code = static_cast<int>(c);
    return true;
}

void proc_kill(Proc& p, bool /*hard*/) { TerminateProcess(p.hproc, 1); }
uint32_t proc_pid(const Proc& p) { return p.pid; }

#else  // ------------------------------------------------------------------------------------------ POSIX

std::unique_ptr<Proc> spawn_proc(const std::string& exe, const std::vector<std::string>& args, const std::string& cwd) {
    int outp[2], inp[2];
    if (::pipe(outp) != 0) throw Error("cannot create a pipe for the engine");
    if (::pipe(inp) != 0) { ::close(outp[0]); ::close(outp[1]); throw Error("cannot create a pipe for the engine"); }
    ::fcntl(outp[0], F_SETFD, FD_CLOEXEC);
    ::fcntl(inp[1], F_SETFD, FD_CLOEXEC);
    std::vector<std::string> store;
    store.push_back(exe);
    for (const auto& a : args) store.push_back(a);
    std::vector<char*> argv;
    for (auto& s : store) argv.push_back(const_cast<char*>(s.c_str()));
    argv.push_back(nullptr);
    long maxfd = ::sysconf(_SC_OPEN_MAX);
    if (maxfd < 64 || maxfd > 4096) maxfd = 4096;
    pid_t parent = ::getpid();
    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(outp[0]); ::close(outp[1]); ::close(inp[0]); ::close(inp[1]);
        throw Error(std::string("cannot start '") + exe + "': fork failed");
    }
    if (pid == 0) {  // child: only async-signal-safe calls
        ::prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (::getppid() != parent) _exit(127);  // the GUI died between fork and prctl
        ::setpgid(0, 0);
        ::dup2(inp[0], 0);
        ::dup2(outp[1], 1);
        ::dup2(outp[1], 2);
        for (int fd = 3; fd < maxfd; ++fd) ::close(fd);
        if (!cwd.empty() && ::chdir(cwd.c_str()) != 0) { /* keep the current folder */ }
        ::execv(exe.c_str(), argv.data());
        _exit(127);
    }
    ::close(outp[1]);
    ::close(inp[0]);
    auto p = std::make_unique<Proc>();
    p->pid = pid;
    p->out_fd = outp[0];
    p->in_fd = inp[1];
    Proc* raw = p.get();
    p->reader = std::thread([raw] {
        char buf[1024];
        for (;;) {
            ssize_t n = ::read(raw->out_fd, buf, sizeof buf);
            if (n > 0) raw->add_output(buf, size_t(n));
            else if (n == 0 || errno != EINTR) break;
        }
    });
    return p;
}

bool proc_exited(Proc& p, int* code) {
    if (p.pid <= 0) return true;
    int st = 0;
    pid_t r = ::waitpid(p.pid, &st, WNOHANG);
    if (r == 0) return false;
    if (r < 0 && errno == EINTR) return false;
    *code = r < 0 ? -1 : WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
    p.pid = -1;
    return true;
}

void proc_kill(Proc& p, bool hard) {
    if (p.pid > 0) ::kill(p.pid, hard ? SIGKILL : SIGTERM);
}
uint32_t proc_pid(const Proc& p) { return uint32_t(p.pid > 0 ? p.pid : 0); }
#endif

}  // namespace

// ================================================================================================ lookups
std::string find_engine_exe() {
    std::string me = self_exe_path();
    if (me.empty()) throw Error("cannot find out where this program is installed");
#ifdef _WIN32
    const char* name = "mysync.exe";
#else
    const char* name = "mysync";
#endif
    fs::path p = fs::u8path(me).parent_path() / name;
    std::error_code ec;
    if (!p.is_absolute()) throw Error("the sync engine path is not absolute");
    if (!fs::is_regular_file(p, ec))
        throw Error(std::string("the sync engine '") + p.u8string() + "' was not found next to the application");
    return p.u8string();
}

// ================================================================================================ instance lock
struct InstanceLock::Impl {
    std::unique_ptr<FileLock> lock;
};
InstanceLock::~InstanceLock() = default;
std::unique_ptr<InstanceLock> InstanceLock::try_acquire(const UserPaths& p, std::string* holder) {
    std::unique_ptr<FileLock> l = FileLock::try_acquire(p.instance_lock, holder);
    if (!l) return nullptr;
    std::unique_ptr<InstanceLock> r(new InstanceLock());
    r->p_ = std::make_unique<Impl>();
    r->p_->lock = std::move(l);
    return r;
}

// ================================================================================================ supervisor
struct Supervisor::Impl {
    struct Slot {
        EngineKind kind;
        bool wanted = false;
        bool restart_req = false;
        bool alive = false;  // a process exists (until it is reaped)
        EngineInfo info;
        std::unique_ptr<Proc> proc;       // owned by the supervisor thread
        int64_t started_at = 0;
        int64_t next_retry_at = 0;
        int consec = 0;                   // consecutive deaths since the last stable run
    };

    SupervisorOptions opts;
    std::string exe;
    mutable std::mutex m;
    std::condition_variable cv;        // wakes the thread
    std::condition_variable idle_cv;   // wakes wait_stopped
    bool quit = false;
    bool started = false;
    std::thread th;
    Slot slots[2];

    Slot& slot(EngineKind k) { return slots[k == EngineKind::Client ? 0 : 1]; }
    const Slot& slot(EngineKind k) const { return slots[k == EngineKind::Client ? 0 : 1]; }

    std::vector<std::string> default_args(EngineKind k) const {
        if (k == EngineKind::Client)
            return {"run", "-c", opts.paths.client_config, "--role", "client", "--user-mode", "--exit-on-stdin-eof"};
        return {"run", "-c", opts.paths.receiver_config, "--role", "server", "--user-mode", "--allow-pairing", "--exit-on-stdin-eof"};
    }
    std::vector<std::string> args_for(EngineKind k) const {
        const auto& o = k == EngineKind::Client ? opts.client_args : opts.receiver_args;
        return o.empty() ? default_args(k) : o;
    }
    bool config_present(EngineKind k) const {
        const auto& o = k == EngineKind::Client ? opts.client_args : opts.receiver_args;
        if (!o.empty()) return true;  // test hook: no configuration needed
        std::error_code ec;
        return fs::is_regular_file(fs::u8path(k == EngineKind::Client ? opts.paths.client_config : opts.paths.receiver_config), ec);
    }

    void emit(const EngineInfo& i) {
        if (opts.on_change) {
            try { opts.on_change(i); } catch (...) {}
        }
    }

    // Asks the engine to stop (closing its stdin = clean stop), then insists. Blocks up to ~stop_grace_ms.
    void stop_proc(Slot& s) {
        Proc& p = *s.proc;
        p.close_stdin();
        int code = 0;
        int64_t t0 = steady_ms();
        bool soft_sent = false;
        while (!proc_exited(p, &code)) {
            int64_t el = steady_ms() - t0;
            if (el > opts.stop_grace_ms) {
                proc_kill(p, true);
                for (int i = 0; i < 100 && !proc_exited(p, &code); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(20));
                break;
            }
            if (!soft_sent && el > opts.stop_grace_ms / 2) { proc_kill(p, false); soft_sent = true; }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        s.proc.reset();  // joins the reader, closes the handles
    }

    void step(Slot& s, int64_t now, std::vector<EngineInfo>& events) {
        bool wanted, rr;
        {
            std::lock_guard<std::mutex> lk(m);
            wanted = s.wanted;
            rr = s.restart_req;
            s.restart_req = false;
        }
        if (s.proc && (!wanted || rr)) {
            stop_proc(s);
            std::lock_guard<std::mutex> lk(m);
            s.alive = false;
            s.info.pid = 0;
            s.info.state = EngineState::Stopped;
            events.push_back(s.info);
            idle_cv.notify_all();
        }
        if (rr) {
            std::lock_guard<std::mutex> lk(m);
            s.info.fast_deaths = 0;
            s.consec = 0;
            s.next_retry_at = 0;
            s.info.next_retry_ms = 0;
            if (s.info.state == EngineState::GaveUp || s.info.state == EngineState::Backoff) s.info.state = EngineState::Stopped;
        }
        if (!wanted) {
            std::lock_guard<std::mutex> lk(m);
            if (s.info.state != EngineState::Stopped) {
                s.info.state = EngineState::Stopped;
                events.push_back(s.info);
            }
            return;
        }
        if (!s.proc) {
            EngineState st;
            {
                std::lock_guard<std::mutex> lk(m);
                st = s.info.state;
            }
            if (st == EngineState::GaveUp) return;
            if (!config_present(s.kind)) {
                std::lock_guard<std::mutex> lk(m);
                if (s.info.state != EngineState::Stopped) { s.info.state = EngineState::Stopped; events.push_back(s.info); }
                return;
            }
            if (now < s.next_retry_at) {
                std::lock_guard<std::mutex> lk(m);
                s.info.next_retry_ms = int(s.next_retry_at - now);
                return;
            }
            try {
                s.proc = spawn_proc(exe, args_for(s.kind), opts.paths.dir);
                s.started_at = now;
                std::lock_guard<std::mutex> lk(m);
                s.alive = true;
                s.info.pid = proc_pid(*s.proc);
                s.info.state = EngineState::Starting;
                s.info.next_retry_ms = 0;
                events.push_back(s.info);
            } catch (const std::exception& e) {
                std::lock_guard<std::mutex> lk(m);
                s.info.last_error = e.what();
                s.consec++;
                s.info.fast_deaths++;
                if (s.info.fast_deaths >= opts.max_fast_deaths) {
                    s.info.state = EngineState::GaveUp;
                } else {
                    s.info.state = EngineState::Backoff;
                    s.next_retry_at = now + backoff(s.consec);
                    s.info.next_retry_ms = backoff(s.consec);
                }
                events.push_back(s.info);
            }
            return;
        }
        int code = 0;
        if (!proc_exited(*s.proc, &code)) {
            if (now - s.started_at > 1500) {
                std::lock_guard<std::mutex> lk(m);
                if (s.info.state == EngineState::Starting) {
                    s.info.state = EngineState::Running;
                    events.push_back(s.info);
                }
                // A run that lasted long enough is stable: forget earlier failures.
                if (now - s.started_at > opts.fast_death_ms && (s.consec != 0 || s.info.fast_deaths != 0)) {
                    s.consec = 0;
                    s.info.fast_deaths = 0;
                }
            }
            return;
        }
        // The engine ended on its own.
        std::string tail = s.proc->last_lines();
        s.proc->release();
        s.proc.reset();
        std::lock_guard<std::mutex> lk(m);
        s.alive = false;
        s.info.pid = 0;
        s.info.last_exit_code = code;
        s.info.last_error = tail.empty() ? "the engine stopped (exit code " + std::to_string(code) + ")" : tail;
        s.info.restarts++;
        bool fast = now - s.started_at < opts.fast_death_ms;
        if (fast) s.info.fast_deaths++;
        else s.info.fast_deaths = 0;
        s.consec = fast ? s.consec + 1 : 1;
        if (s.info.fast_deaths >= opts.max_fast_deaths) {
            s.info.state = EngineState::GaveUp;
            s.info.next_retry_ms = 0;
        } else {
            s.info.state = EngineState::Backoff;
            int d = backoff(s.consec);
            s.next_retry_at = now + d;
            s.info.next_retry_ms = d;
        }
        events.push_back(s.info);
        idle_cv.notify_all();
    }

    int backoff(int consec) const {
        if (opts.backoff_ms.empty()) return 1000;
        size_t i = size_t(std::max(1, consec) - 1);
        return opts.backoff_ms[std::min(i, opts.backoff_ms.size() - 1)];
    }

    void loop() {
        for (;;) {
            std::vector<EngineInfo> events;
            {
                std::lock_guard<std::mutex> lk(m);
                if (quit) break;
            }
            int64_t now = steady_ms();
            for (Slot& s : slots) step(s, now, events);
            for (const EngineInfo& e : events) emit(e);
            std::unique_lock<std::mutex> lk(m);
            if (quit) break;
            cv.wait_for(lk, std::chrono::milliseconds(100));
        }
        // Shutting down: stop every engine and wait until its locks are released.
        std::vector<EngineInfo> events;
        for (Slot& s : slots) {
            if (s.proc) {
                stop_proc(s);
                std::lock_guard<std::mutex> lk(m);
                s.alive = false;
                s.info.pid = 0;
            }
            std::lock_guard<std::mutex> lk(m);
            s.wanted = false;
            if (s.info.state != EngineState::Stopped) {
                s.info.state = EngineState::Stopped;
                events.push_back(s.info);
            }
        }
        idle_cv.notify_all();
        for (const EngineInfo& e : events) emit(e);
    }
};

Supervisor::Supervisor(SupervisorOptions opts) : p_(new Impl) {
    p_->opts = std::move(opts);
    p_->slots[0].kind = EngineKind::Client;
    p_->slots[1].kind = EngineKind::Receiver;
    p_->slots[0].info.kind = EngineKind::Client;
    p_->slots[1].info.kind = EngineKind::Receiver;
    p_->slots[0].info.control_name = p_->opts.paths.client_control_name;
    p_->slots[1].info.control_name = p_->opts.paths.receiver_control_name;
    p_->slots[0].wanted = p_->opts.run_client;
    p_->slots[1].wanted = p_->opts.run_receiver;
}

Supervisor::~Supervisor() { stop_all(); }

void Supervisor::start() {
    Impl& im = *p_;
    {
        std::lock_guard<std::mutex> lk(im.m);
        if (im.started) return;
    }
    std::string exe = im.opts.mysync_exe.empty() ? find_engine_exe() : im.opts.mysync_exe;
    std::error_code ec;
    fs::path ep = fs::u8path(exe);
    if (!ep.is_absolute() || !fs::is_regular_file(ep, ec))
        throw Error("the sync engine '" + exe + "' does not exist or is not an absolute path");
    im.exe = ep.u8string();
    std::lock_guard<std::mutex> lk(im.m);
    im.started = true;
    im.quit = false;
    im.th = std::thread([&im] { im.loop(); });
}

void Supervisor::stop_all() {
    Impl& im = *p_;
    std::thread t;
    {
        std::lock_guard<std::mutex> lk(im.m);
        if (!im.started) return;
        im.quit = true;
        im.started = false;
        t = std::move(im.th);
    }
    im.cv.notify_all();
    if (t.joinable()) t.join();
}

void Supervisor::set_receiver_enabled(bool on) {
    {
        std::lock_guard<std::mutex> lk(p_->m);
        p_->slot(EngineKind::Receiver).wanted = on;
    }
    p_->cv.notify_all();
}

void Supervisor::set_client_enabled(bool on) {
    {
        std::lock_guard<std::mutex> lk(p_->m);
        p_->slot(EngineKind::Client).wanted = on;
    }
    p_->cv.notify_all();
}

void Supervisor::restart(EngineKind k) {
    {
        std::lock_guard<std::mutex> lk(p_->m);
        p_->slot(k).restart_req = true;
    }
    p_->cv.notify_all();
}

bool Supervisor::wait_stopped(EngineKind k, int timeout_ms) {
    std::unique_lock<std::mutex> lk(p_->m);
    Impl::Slot& s = p_->slot(k);
    // "Stopped" means no process; a wanted engine that is merely between restarts also has none.
    return p_->idle_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] { return !s.alive; });
}

std::vector<EngineInfo> Supervisor::info() const {
    std::lock_guard<std::mutex> lk(p_->m);
    return {p_->slots[0].info, p_->slots[1].info};
}

EngineInfo Supervisor::info(EngineKind k) const {
    std::lock_guard<std::mutex> lk(p_->m);
    return p_->slot(k).info;
}

}  // namespace mysync::simple
