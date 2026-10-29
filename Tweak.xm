// Add compilation function pointer type
typedef char* (*luau_compile_t)(const char* source, size_t source_size, void* options, size_t* bytecode_size);

void ExecuteLuauBytecode(const char* source, size_t size) {
    if (!g_live_L) {
        SporkLog(@"L is NULL. Wait for game.");
        return;
    }
    
    uintptr_t base = get_robloxlib_base();
    if (!base) {
        SporkLog(@"RobloxLib base is NULL.");
        return;
    }
    
    luau_compile_t luau_compile = (luau_compile_t)(base + OFFSET_LUAU_COMPILE);
    luau_load_t luau_load = (luau_load_t)(base + 0x44bc110);   // Keep your offset, but verify it's still correct
    lua_pcall_t lua_pcall = (lua_pcall_t)(base + 0x4490fec);
    lua_newthread_t lua_newthread = (lua_newthread_t)(base + 0x448df3c);
    luaL_sandboxthread_t luaL_sandboxthread = (luaL_sandboxthread_t)(base + 0x1a12ad4);
    
    // Step 1: Compile source code to bytecode
    size_t bytecode_size = 0;
    char* bytecode = luau_compile(source, size, NULL, &bytecode_size);
    if (!bytecode || bytecode_size == 0) {
        SporkLog(@"luau_compile failed: no bytecode produced.");
        return;
    }
    
    SporkLog(@"Compiled bytecode size: %zu", bytecode_size);
    
    // Step 2: Create thread and execute
    in_hook_exec = 1;
    int sig = sigsetjmp(hook_jump_buffer, 1);
    if (sig == 0) {
        void* new_L = lua_newthread(g_live_L);
        if (new_L) {
            luaL_sandboxthread(new_L);
            int status = luau_load(new_L, "SporkScript", bytecode, bytecode_size, 0);
            if (status == 0) {
                lua_pcall(new_L, 0, 0, 0);
                SporkLog(@"Executed successfully!");
            } else {
                SporkLog(@"luau_load failed. Status: %d", status);
            }
        }
        in_hook_exec = 0;
    } else {
        in_hook_exec = 0;
        SporkLog(@"CRASH CAUGHT: Signal %d", sig);
    }
    
    free(bytecode);
}
