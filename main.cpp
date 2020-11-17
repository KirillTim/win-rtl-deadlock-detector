#include <iostream>
#include <vector>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <thread>
#include <atomic>

#include <Windows.h>
#include <process.h>

using namespace std;

struct StackBounds {
    StackBounds(u_char *stackBase, size_t stackSize) : stack_base(stackBase), stack_size(stackSize) {}

    u_char *stack_base;
    size_t stack_size;

    u_char *stack_end() const {
        return stack_base - stack_size;
    }

    bool is_inside(const u_char *sp) const {
        return stack_base > sp && sp >= stack_end();
    }

    bool is_inside(DWORD64 sp) const {
        return is_inside((u_char *) sp);
    }
};

u_char* stack_base(const void* rsp) {
    MEMORY_BASIC_INFORMATION minfo;
    u_char* stack_bottom;
    size_t stack_size;

    VirtualQuery(rsp, &minfo, sizeof(minfo));
    stack_bottom =  (u_char*)minfo.AllocationBase;
    stack_size = minfo.RegionSize;

    // Add up the sizes of all the regions with the same
    // AllocationBase.
    while (1) {
        VirtualQuery(stack_bottom+stack_size, &minfo, sizeof(minfo));
        if (stack_bottom == (void*)minfo.AllocationBase) {
            stack_size += minfo.RegionSize;
        } else {
            break;
        }
    }
    return stack_bottom + stack_size;
}

StackBounds get_stack_bounds(const void *rsp) {
    u_char *base = stack_base(rsp);
    size_t size;
    MEMORY_BASIC_INFORMATION minfo;
    VirtualQuery(rsp, &minfo, sizeof(minfo));
    size = (size_t) base - (size_t) minfo.AllocationBase;
    return {base, size};
}


SYSTEM_INFO system_info;

bool is_valid_ip(uintptr_t ptr) noexcept {
    const void* vptr = reinterpret_cast<const void*>(ptr);
    if (vptr < system_info.lpMinimumApplicationAddress || system_info.lpMaximumApplicationAddress < vptr)
        return false;

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(vptr, &mbi, sizeof mbi))
        return false;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
        return false;
    return mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
}

bool is_valid_sp(uintptr_t ptr, const StackBounds& stack_bounds) noexcept {
    if (!stack_bounds.is_inside(ptr)) return false;

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(reinterpret_cast<const void*>(ptr), &mbi, sizeof mbi))
        return false;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
        return false;
    return mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
}

bool is_valid_context(const CONTEXT* context, const StackBounds& stack_bounds) noexcept {
    return is_valid_ip(context->Rip) && is_valid_sp(context->Rsp, stack_bounds);
}

atomic<chrono::time_point<chrono::steady_clock>> last_sample_time = chrono::steady_clock::now();

int getNativeTrace(CONTEXT* ucontext, int max_depth) {
    CONTEXT ctx;
    ctx = *ucontext;
    auto stack_bounds = get_stack_bounds((void*)ctx.Rsp);
    if (!is_valid_context(&ctx, stack_bounds)) {
        return 0;
    }
    int depth = 0;
    while (depth < max_depth && is_valid_context(&ctx, stack_bounds)) {
        const void* pc = (const void*)ctx.Rip;
        depth++;

        uint64_t _Image_base;
        RUNTIME_FUNCTION* _Function_entry = RtlLookupFunctionEntry(ctx.Rip, &_Image_base, nullptr);
        last_sample_time.store(chrono::steady_clock::now());
        if (_Function_entry) {
            void* _Handler_data;
            DWORD64 _Establisher_frame;
            RtlVirtualUnwind(0, _Image_base, ctx.Rip, _Function_entry, &ctx, &_Handler_data, &_Establisher_frame, nullptr);
        } else {
            // Note: Nested functions that do not use any stack space or nonvolatile registers are not required to have unwind info (ex. USER32!ZwUserCreateWindowEx).
            ctx.Rip = *reinterpret_cast<uint64_t const*>(ctx.Rsp);
            ctx.Rsp += sizeof(uint64_t);
        }

    }

    return depth;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////




void foreverLoadDllLoop(void* ignored) {
    cerr << "foreverLoadDllLoop is working on thread " << GetCurrentThreadId() << endl;
    const char *dllPath = R"(C:\Users\kirill.timofeev\Downloads\jbrsdk-11_0_8-windows-x64-fastdebug-b1026.tar\jbrsdk\bin\server\jvm.dll)";
    for (;;) {
        HMODULE jvmDll = LoadLibraryA(dllPath);
        if (jvmDll == nullptr) {
            cerr << "LoadLibraryA error:" << GetLastError() << endl;
            break;
        }
        auto res = FreeLibrary(jvmDll);
        if (!res) {
            cerr << "FreeLibrary error:" << GetLastError() << endl;
            break;
        }
    }
}

[[noreturn]] void samplingDeadlockMonitor(void* data) {
    HANDLE targetThread = (HANDLE) data;
    cerr << "samplingDeadlockMonitor started" << endl;
    for (;;) {
        auto now = chrono::steady_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(now - last_sample_time.load()).count();
        if (duration > 5000) {
            ResumeThread(targetThread);
            cerr << "Deadlock happened, resuming target thread" << endl;
        }
        this_thread::sleep_for(chrono::milliseconds(1000));
    }
    cerr << "Deadlock happened, waiting for debugger..." << endl;
    for (;;) {}
}


void sampler(void* ignored) {
    int target_tid;
    cout << "Enter target tid" << endl;
    cin >> target_tid;
    const int flags = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                      THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION;
    HANDLE threadHandle = OpenThread(flags, false, target_tid);
    if (threadHandle == nullptr) {
        cerr << "threadHandle == nullptr" << endl;
        return;
    }

    _beginthread(samplingDeadlockMonitor, 0, threadHandle);

    for (;;) {
        CONTEXT ctxt;
        ctxt.ContextFlags = CONTEXT_FULL;
        DWORD suspend_count = SuspendThread(threadHandle);
        if (GetThreadContext(threadHandle, &ctxt) == 0) {
            cerr << "cant GetThreadContext" << endl;
            break;
        }
        int stack_depth = getNativeTrace(&ctxt, 2048);
        //last_sample_time.store(chrono::steady_clock::now());

        ResumeThread(threadHandle);
        cerr << "stack depth: " << stack_depth << endl;
        this_thread::sleep_for(chrono::milliseconds(17));
    }
}


int main() {
    GetSystemInfo(&system_info);
    _beginthread(foreverLoadDllLoop, 0, nullptr);
    _beginthread(sampler, 0, nullptr);
    cerr << "Waiting for deadlock..." << endl;
    for (;;) {

    }
    return 0;
}
